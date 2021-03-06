<?php
declare(strict_types=1);
namespace Oire\Iridium;

use DateTimeImmutable;
use DateTimeZone;
use Oire\Iridium\Exception\Base64Exception;
use Oire\Iridium\Exception\CryptException;
use Oire\Iridium\Exception\InvalidTokenException;
use Oire\Iridium\Exception\OsstException;
use Oire\Iridium\Key\SymmetricKey;
use PDO;
use PDOException;
use Throwable;

/**
 * Iridium, a security library for hashing passwords, encrypting data and managing secure tokens
 * Implements the split token authentication model proposed by Paragon Initiatives.
 * Copyright © 2021 Andre Polykanine also known as Menelion Elensúlë, The Magical Kingdom of Oirë, https://github.com/Oire
 * Idea Copyright © 2017 Paragon Initiatives, https://paragonie.com/blog/2017/02/split-tokens-token-based-authentication-protocols-without-side-channels
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 */
final class Osst
{
    public const TABLE_NAME = 'iridium_tokens';
    public const DEFAULT_EXPIRATION_DATE_FORMAT = 'Y-m-d H:i:s';
    public const DEFAULT_EXPIRATION_DATE_OFFSET = '+14 days';
    public const DEFAULT_EXPIRATION_TIME_OFFSET = 1209600;

    private const TOKEN_SIZE = 36;
    private const SELECTOR_SIZE = 16;
    private const VERIFIER_SIZE = 20;

    /** @var PDO */
    private $dbConnection;

    /** @var string|null */
    private $token;

    /** @var string|null */
    private $selector;

    /** @var string|null */
    private $hashedVerifier;

    /** @var int */
    private $userId = 0;

    /** @var int */
    private $expirationTime = 0;

    /** @var int|null */
    private $tokenType;

    /** @var string|null */
    private $additionalInfo;

    /**
     * Instantiate a new Osst object.
     * @param PDO               $dbConnection                Connection to your database
     * @param string|null       $token                       A user-provided token. Provide this only if you received a token from the user
     * @param SymmetricKey|null $additionalInfoDecryptionKey The Iridium key to decrypt additional info for the token
     */
    public function __construct(PDO $dbConnection, ?string $token = null, ?SymmetricKey $additionalInfoDecryptionKey = null)
    {
        $this->dbConnection = $dbConnection;

        try {
            $this->dbConnection->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $this->dbConnection->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
            $this->dbConnection->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
            $this->dbConnection->setAttribute(PDO::ATTR_STRINGIFY_FETCHES, false);
            $this->dbConnection->setAttribute(PDO::ATTR_CASE, PDO::CASE_NATURAL);
        } catch (PDOException $e) {
            throw InvalidTokenException::sqlError($e);
        }

        if ($token) {
            $this->setToken($token, $additionalInfoDecryptionKey);
        } else {
            $rawToken = random_bytes(self::TOKEN_SIZE);
            $this->token = Base64::encode($rawToken);
            $this->selector = Base64::encode(mb_substr($rawToken, 0, self::SELECTOR_SIZE, Crypt::STRING_ENCODING_8BIT));
            $this->hashedVerifier = Base64::encode(hash(Crypt::HASH_FUNCTION, mb_substr($rawToken, self::SELECTOR_SIZE, self::VERIFIER_SIZE, Crypt::STRING_ENCODING_8BIT), true));
        }
    }

    /**
     * Get the connection to the database.
     * @return PDO Returns the connection to the database as a PDO object
     */
    public function getDbConnection(): PDO
    {
        return $this->dbConnection;
    }

    /**
     * Get the token.
     * @throws OsstException If the token was not set or created beforehand
     * @return string        Returns the token
     */
    public function getToken(): string
    {
        if (!$this->token) {
            throw OsstException::tokenNotSet();
        }

        return $this->token;
    }

    /**
     * Set and validate a user-provided token.
     * @param  string                $token                       The token provided by the user
     * @param  SymmetricKey|null     $additionalInfoDecryptionKey If not empty, the previously additional info for the token will be decrypted
     * @throws InvalidTokenException
     */
    private function setToken(string $token, ?SymmetricKey $additionalInfoDecryptionKey = null): void
    {
        try {
            $rawToken = Base64::decode($token);
        } catch (Base64Exception $e) {
            throw InvalidTokenException::invalidTokenFormat($e->getMessage(), $e);
        }

        if (mb_strlen($rawToken, Crypt::STRING_ENCODING_8BIT) !== self::TOKEN_SIZE) {
            throw InvalidTokenException::invalidTokenLength();
        }

        $selector = Base64::encode(mb_substr($rawToken, 0, self::SELECTOR_SIZE, Crypt::STRING_ENCODING_8BIT));

        $sql = sprintf('SELECT user_id, token_type, selector, verifier, additional_info, expiration_time FROM %s WHERE selector = :selector', self::TABLE_NAME);
        $statement = $this->dbConnection->prepare($sql);

        if (!$statement) {
            /** @var string */
            $errorMessage = $this->dbConnection->errorInfo()[2] ?? 'Unknown PDO error';
            throw InvalidTokenException::pdoStatementError($errorMessage);
        }

        try {
            $statement->execute([':selector' => $selector]);
        } catch (PDOException $e) {
            throw InvalidTokenException::sqlError($e);
        }

        /** @var string[] */
        $result = $statement->fetch();

        if (!$result) {
            throw InvalidTokenException::selectorError();
        }

        $verifier = Base64::encode(hash(Crypt::HASH_FUNCTION, mb_substr($rawToken, self::SELECTOR_SIZE, self::VERIFIER_SIZE, Crypt::STRING_ENCODING_8BIT), true));

        if (isset($result['verifier'])) {
            $validVerifier = $result['verifier'];
        } else {
            throw InvalidTokenException::verifierError();
        }

        if (!hash_equals($verifier, $validVerifier)) {
            throw InvalidTokenException::verifierError();
        }

        $this->token = $token;
        $this->selector = $selector;
        $this->hashedVerifier = $verifier;

        if (isset($result['user_id'])) {
            $this->userId = (int) $result['user_id'];
        } else {
            throw OsstException::invalidUserId(0);
        }

        if (isset($result['expiration_time'])) {
            $this->expirationTime = (int) $result['expiration_time'];
        } else {
            throw OsstException::emptyExpirationTime();
        }

        $this->tokenType = isset($result['token_type']) ? (int) $result['token_type'] : null;

        if (isset($result['additional_info'])) {
            if ($additionalInfoDecryptionKey) {
                try {
                    $this->additionalInfo = Crypt::decrypt($result['additional_info'], $additionalInfoDecryptionKey);
                } catch (CryptException $e) {
                    throw OsstException::additionalInfoDecryptionError($e);
                }
            } else {
                $this->additionalInfo = $result['additional_info'];
            }
        }
    }

    /**
     * Get the ID of the user the token belongs to.
     */
    public function getUserId(): int
    {
        return $this->userId;
    }

    /**
     * Set the ID of the user the token belongs to.
     * @param  int           $userId The ID of the user the token belongs to. Must be a positive integer.
     * @throws OsstException
     * @return $this
     */
    public function setUserId(int $userId): self
    {
        if ($this->userId) {
            throw OsstException::propertyAlreadySet('User ID');
        }

        if ($userId <= 0) {
            throw OsstException::invalidUserId($userId);
        }

        $this->userId = $userId;

        return $this;
    }

    /**
     * Get the expiration time of the token as timestamp.
     */
    public function getExpirationTime(): int
    {
        return $this->expirationTime;
    }

    /**
     * Check if the token is eternal, i.e., never expires.
     * @throws OsstException If the expiration time is empty
     * @return bool          True if the token never expires, false otherwise. Also returns false if an eternal token has been revoked
     */
    public function isEternal(): bool
    {
        return $this->expirationTime === 0 && !$this->isExpired();
    }

    /**
     * Get the expiration time of the token as a DateTime immutable object.
     * @throws OsstException     If the token never expires
     * @return DateTimeImmutable Returns the expiration time as a DateTimeImmutable in the default time zone set in PHP settings
     */
    public function getExpirationDate(): DateTimeImmutable
    {
        if ($this->isEternal()) {
            throw OsstException::tokenNeverExpires();
        }

        return (new DateTimeImmutable(sprintf('@%s', $this->expirationTime)))
            ->setTimezone(new DateTimeZone(date_default_timezone_get()));
    }

    /**
     * Get the expiration time of the token in a given format.
     * @param string $format A valid date format. Defaults to `'Y-m-d H:i:s'`
     * @see https://www.php.net/manual/en/function.date.php
     * @throws OsstException if the date formatting fails or the token never expires
     * @return string        Returns the expiration time as date string in given format
     */
    public function getExpirationDateFormatted(string $format = self::DEFAULT_EXPIRATION_DATE_FORMAT): string
    {
        if ($this->isEternal()) {
            throw OsstException::tokenNeverExpires();
        }

        try {
            return (new DateTimeImmutable(sprintf('@%s', $this->expirationTime)))
                ->setTimezone(new DateTimeZone(date_default_timezone_get()))
                ->format($format);
        } catch (Throwable $e) {
            throw new OsstException(sprintf('Unable to format expiration date: %s.', $e->getMessage()), $e);
        }
    }

    /**
     * Set the expiration time for the token using timestamp.
     * @param  int           $timestamp The timestamp when the token should expire, defaults to 1209600 seconds, i.e., 14 days
     * @throws OsstException
     * @return $this
     */
    public function setExpirationTime(?int $timestamp = null): self
    {
        if ($this->expirationTime) {
            throw OsstException::propertyAlreadySet('Expiration time');
        }

        $timestamp = $timestamp ?? time() + self::DEFAULT_EXPIRATION_TIME_OFFSET;

        if ($timestamp !== 0 && $timestamp <= time()) {
            throw OsstException::expirationTimeInPast($timestamp);
        }

        $this->expirationTime = $timestamp;

        return $this;
    }

    /**
     * Set the expiration time for the token using relative time.
     * @param string $offset The time interval the token expires in. The default value is `'+14 days'`. Must be a valid relative date format.
     * @see https://www.php.net/manual/en/datetime.formats.relative.php
     * @throws OsstException
     * @return $this
     */
    public function setExpirationOffset(string $offset = self::DEFAULT_EXPIRATION_DATE_OFFSET): self
    {
        if ($this->expirationTime) {
            throw OsstException::propertyAlreadySet('Expiration time');
        }

        if (!$offset) {
            throw OsstException::emptyExpirationOffset();
        }

        try {
            $this->expirationTime = (new DateTimeImmutable())->modify($offset)->getTimestamp();

            if ($this->expirationTime <= time()) {
                throw OsstException::expirationTimeInPast($this->expirationTime);
            }
        } catch (Throwable $e) {
            throw new OsstException(sprintf('Invalid expiration offset "%s": %s', $offset, $e->getMessage()), $e);
        }

        return $this;
    }

    /**
     * Set the expiration time for the token using DateTime immutable object.
     * @param  DateTimeImmutable $expirationDate The date the token should expire at
     * @throws OsstException
     * @return $this
     */
    public function setExpirationDate(DateTimeImmutable $expirationDate): self
    {
        $this->expirationTime = $expirationDate->getTimestamp();

        if ($this->expirationTime <= time()) {
            throw OsstException::expirationTimeInPast($this->expirationTime);
        }

        return $this;
    }

    /**
     * Makes the token eternal, so it will never expire.
     * @return $this
     */
    public function makeEternal(): self
    {
        $this->expirationTime = 0;

        return $this;
    }

    /**
     * Check if the token is expired.
     * @throws OsstException if the expiration time is empty
     * @return bool          True if the token is expired, false otherwise
     */
    public function isExpired(): bool
    {
        return $this->expirationTime !== 0 && $this->expirationTime <= time();
    }

    /**
     * @deprecated 1.1 Use isExpired() instead
     * @psalm-suppress PossiblyUnusedMethod
     */
    public function tokenIsExpired(): bool
    {
        return $this->isExpired();
    }

    /**
     * Get the token type.
     * @return int|null The token type or null if it was not set before
     */
    public function getTokenType(): ?int
    {
        return $this->tokenType;
    }

    /**
     * Set the token type.
     * @param  int|null $tokenType Set this if you want to categorize your tokens by type. The default value is null
     * @return $this
     */
    public function setTokenType(?int $tokenType): self
    {
        $this->tokenType = $tokenType;

        return $this;
    }

    /**
     * Get the additional info for the token.
     * @return string|null The additional info or null if it was not set before
     */
    public function getAdditionalInfo(): ?string
    {
        return $this->additionalInfo;
    }

    /**
     * Set the additional info for the token.
     * @param  string|null       $additionalInfo Any additional info you want to convey along with the token, as string
     * @param  SymmetricKey|null $encryptionKey  If not empty, the data will be encrypted
     * @return $this
     */
    public function setAdditionalInfo(?string $additionalInfo, ?SymmetricKey $encryptionKey = null): self
    {
        if ($additionalInfo) {
            if ($encryptionKey) {
                try {
                    $this->additionalInfo = Crypt::encrypt($additionalInfo, $encryptionKey);
                } catch (CryptException $e) {
                    throw OsstException::additionalInfoEncryptionError($e);
                }
            } else {
                $this->additionalInfo = $additionalInfo;
            }
        }

        return $this;
    }

    /**
     * Store the token in the database.
     * @throws InvalidTokenException If SQL error occurs
     * @throws OsstException         if not enough data are provided
     * @return $this
     */
    public function persist(): self
    {
        if (!$this->token) {
            throw OsstException::tokenNotSet();
        }

        if ($this->userId <= 0) {
            throw OsstException::invalidUserId($this->userId);
        }

        $sql = sprintf('INSERT INTO %s (user_id, token_type, selector, verifier, additional_info, expiration_time) VALUES (:userid, :tokentype, :selector, :verifier, :additional, :expires)', self::TABLE_NAME);
        $statement = $this->dbConnection->prepare($sql);

        if (!$statement) {
            /** @var string */
            $errorMessage = $this->dbConnection->errorInfo()[2] ?? 'Unknown PDO error';
            throw InvalidTokenException::pdoStatementError($errorMessage);
        }

        try {
            $statement->execute([
                ':userid' => $this->userId,
                ':tokentype' => $this->tokenType,
                ':selector' => $this->selector,
                ':verifier' => $this->hashedVerifier,
                ':additional' => $this->additionalInfo,
                ':expires' => $this->expirationTime
            ]);
        } catch (PDOException $e) {
            throw InvalidTokenException::sqlError($e);
        }

        return $this;
    }

    /**
     * Revoke the token.
     * @param  bool          $deleteToken If true, the token will be deleted from the database. If false (default), it will be updated with the expiration time set in the past
     * @throws OsstException
     */
    public function revokeToken(bool $deleteToken = false): void
    {
        if (!$this->token) {
            throw OsstException::tokenNotSet();
        }

        $this->expirationTime = time() - self::DEFAULT_EXPIRATION_TIME_OFFSET;

        if ($deleteToken) {
            $statement = $this->dbConnection->prepare(sprintf('DELETE FROM %s WHERE selector = :selector', self::TABLE_NAME));

            if (!$statement) {
                /** @var string */
                $errorMessage = $this->dbConnection->errorInfo()[2] ?? 'Unknown PDO error';
                throw InvalidTokenException::pdoStatementError($errorMessage);
            }

            try {
                $statement->execute([':selector' => $this->selector]);
            } catch (PdoException $e) {
                throw InvalidTokenException::sqlError($e);
            }
        } else {
            $statement = $this->dbConnection->prepare(sprintf('UPDATE %s SET expiration_time = :expires WHERE selector = :selector', self::TABLE_NAME));

            if (!$statement) {
                /** @var string */
                $errorMessage = $this->dbConnection->errorInfo()[2] ?? 'Unknown PDO error';
                throw InvalidTokenException::pdoStatementError($errorMessage);
            }

            try {
                $statement->execute([
                    ':expires' => $this->expirationTime,
                    ':selector' => $this->selector
                ]);
            } catch (PdoException $e) {
                throw InvalidTokenException::sqlError($e);
            }
        }

        $this->token = null;
        $this->selector = null;
        $this->hashedVerifier = null;
    }

    /**
     * Delete all expired tokens from database.
     * @param  PDO $dbConnection Connection to the database
     * @return int Returns the number of deleted tokens
     */
    public static function clearExpiredTokens(PDO $dbConnection): int
    {
        $statement = $dbConnection->prepare(sprintf('DELETE FROM %s WHERE expiration_time <= :time', self::TABLE_NAME));

        if (!$statement) {
            /** @var string */
            $errorMessage = $dbConnection->errorInfo()[2] ?? 'Unknown PDO error';
            throw InvalidTokenException::pdoStatementError($errorMessage);
        }

        try {
            $statement->execute([':time' => time()]);

            return $statement->rowCount();
        } catch (PdoException $e) {
            throw InvalidTokenException::sqlError($e);
        }
    }
}
