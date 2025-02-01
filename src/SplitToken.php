<?php

declare(strict_types=1);

namespace Oire\Iridium;

use DateTimeImmutable;
use DateTimeZone;
use Oire\Iridium\Exception\Base64Exception;
use Oire\Iridium\Exception\CryptException;
use Oire\Iridium\Exception\InvalidTokenException;
use Oire\Iridium\Exception\SplitTokenException;
use Oire\Iridium\Key\SharedKey;
use PDO;
use PDOException;
use Throwable;

/**
 * Iridium, a security library for hashing passwords, encrypting data and managing secure tokens
 * Implements the split token authentication model proposed by Paragon Initiatives.
 * Copyright © 2021-2025 André Polykanine also known as Menelion Elensúlë, Oire Software, https://github.com/Oire
 * Idea Copyright © 2017 Paragon Initiatives.
 *
 * @see https://paragonie.com/blog/2017/02/split-tokens-token-based-authentication-protocols-without-side-channels
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
final class SplitToken
{
    public const TABLE_NAME = 'iridium_tokens';
    public const DEFAULT_EXPIRATION_DATE_FORMAT = 'Y-m-d H:i:s';
    public const DEFAULT_EXPIRATION_TIME_OFFSET = '+1 hour';
    private const TOKEN_SIZE = 36;
    private const SELECTOR_SIZE = 16;
    private const VERIFIER_SIZE = 20;
    private ?string $token = null;
    private ?string $selector = null;
    private ?string $hashedVerifier = null;

    /**
     * Instantiate a new SplitToken object.
     *
     * @param PDO         $dbConnection   Connection to the database
     * @param int|null    $expirationTime expiration time of the token. Set to null if the token should not expire
     * @param int|null    $userId         The ID of the user in the database
     * @param int|null    $tokenType      A custom type for the token, most likely taken from an enum
     * @param string|null $additionalInfo Some supplementary information attached to the token, like a JSON object
     */
    private function __construct(
        private PDO $dbConnection,
        private ?int $expirationTime = null,
        private ?int $userId = null,
        private ?int $tokenType = null,
        private ?string $additionalInfo = null
    ) {
        try {
            $this->dbConnection->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $this->dbConnection->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
            $this->dbConnection->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
            $this->dbConnection->setAttribute(PDO::ATTR_STRINGIFY_FETCHES, false);
            $this->dbConnection->setAttribute(PDO::ATTR_CASE, PDO::CASE_NATURAL);
        } catch (PDOException $e) {
            throw InvalidTokenException::sqlError($e);
        }
    }

    /**
     * Create a new split token.
     *
     * @param PDO             $dbConnection      Connection to the database
     * @param int|string|null $expirationTime    expiration time of the token. Set to null if the token should not expire
     * @param int|null        $userId            The ID of the user in the database
     * @param int|null        $tokenType         A custom type for the token, most likely taken from an enum
     * @param string|null     $additionalInfo    Some supplementary information attached to the token, like a JSON object
     * @param SharedKey|null  $additionalInfoKey An Iridium key to encrypt the additional info or decrypt it if it was encrypted before
     *
     * @return self Returns a newly created SplitToken
     */
    public static function create(
        PDO $dbConnection,
        int|string|null $expirationTime = 0,
        ?int $userId = null,
        ?int $tokenType = null,
        ?string $additionalInfo = null,
        ?SharedKey $additionalInfoKey = null
    ): self
    {
        $splitToken = new self($dbConnection);
        $rawToken = random_bytes(self::TOKEN_SIZE);
        $splitToken->token = Base64::encode($rawToken);
        $splitToken->selector = Base64::encode(mb_substr($rawToken, 0, self::SELECTOR_SIZE, Crypt::STRING_ENCODING_8BIT));
        $splitToken->hashedVerifier = Base64::encode(
            hash(
                Crypt::HASH_FUNCTION,
                mb_substr($rawToken, self::SELECTOR_SIZE, self::VERIFIER_SIZE, Crypt::STRING_ENCODING_8BIT),
                true
            )
        );

        $splitToken->expirationTime = is_string($expirationTime)
            ? (new DateTimeImmutable($expirationTime))->getTimestamp()
            : ($expirationTime === 0 ? (new DateTimeImmutable(self::DEFAULT_EXPIRATION_TIME_OFFSET))->getTimestamp() : $expirationTime);

        if ($userId !== null && $userId <= 0) {
            throw SplitTokenException::invalidUserId($userId);
        }

        $splitToken->userId = $userId;
        $splitToken->tokenType = $tokenType;

        if ($additionalInfo !== null && $additionalInfoKey !== null) {
            try {
                $splitToken->additionalInfo = Crypt::encrypt($additionalInfo, $additionalInfoKey);
            } catch (CryptException $e) {
                throw SplitTokenException::additionalInfoEncryptionError($e);
            }
        } else {
            $splitToken->additionalInfo = $additionalInfo;
        }

        return $splitToken;
    }

    /**
     * Get the token.
     *
     * @return string|null Returns the token
     */
    public function getToken(): ?string
    {
        return $this->token;
    }

    /**
     * Set and validate a user-provided token.
     *
     * @param string|null    $token             The token provided by the user
     * @param PDO            $dbConnection      Connection to the database
     * @param SharedKey|null $additionalInfoKey If not empty, the encrypted additional info will be decrypted
     *
     * @throws InvalidTokenException
     */
    public static function fromString(?string $token, PDO $dbConnection, ?SharedKey $additionalInfoKey = null): self
    {
        if ($token === null) {
            throw InvalidTokenException::invalidTokenLength();
        }

        $splitToken = new self($dbConnection);

        try {
            $rawToken = Base64::decode($token);
        } catch (Base64Exception $e) {
            throw InvalidTokenException::invalidTokenFormat($e->getMessage(), $e);
        }

        if (self::TOKEN_SIZE !== mb_strlen($rawToken, Crypt::STRING_ENCODING_8BIT)) {
            throw InvalidTokenException::invalidTokenLength();
        }

        $selector = Base64::encode(mb_substr($rawToken, 0, self::SELECTOR_SIZE, Crypt::STRING_ENCODING_8BIT));

        $sql = sprintf(
            'SELECT
                user_id, token_type, selector, verifier, additional_info, expiration_time
                FROM %s
                WHERE selector = :selector',
            self::TABLE_NAME
        );
        $statement = $splitToken->dbConnection->prepare($sql);

        if (!$statement) {
            $errorMessage = $splitToken->dbConnection->errorInfo()[2] ?? 'Unknown PDO error';
            throw InvalidTokenException::pdoStatementError($errorMessage);
        }

        try {
            $statement->execute([':selector' => $selector]);
        } catch (PDOException $e) {
            throw InvalidTokenException::sqlError($e);
        }

        /** @var array<string, string|null> */
        $result = $statement->fetch();

        if (!$result) {
            throw InvalidTokenException::selectorError();
        }

        $verifier = Base64::encode(
            hash(
                Crypt::HASH_FUNCTION,
                mb_substr($rawToken, self::SELECTOR_SIZE, self::VERIFIER_SIZE, Crypt::STRING_ENCODING_8BIT),
                true
            )
        );

        if ($result['verifier'] === null || !hash_equals($verifier, $result['verifier'])) {
            throw InvalidTokenException::verifierError();
        }

        $splitToken->token = $token;
        $splitToken->selector = $selector;
        $splitToken->hashedVerifier = $verifier;
        $splitToken->userId = $result['user_id'] !== null ? (int) $result['user_id'] : null;
        $splitToken->expirationTime = $result['expiration_time'] !== null ? (int) $result['expiration_time'] : null;
        $splitToken->tokenType = $result['token_type'] !== null ? (int) $result['token_type'] : null;

        if ($result['additional_info'] !== null) {
            if ($additionalInfoKey !== null) {
                try {
                    $splitToken->additionalInfo = Crypt::decrypt($result['additional_info'], $additionalInfoKey);
                } catch (CryptException $e) {
                    throw SplitTokenException::additionalInfoDecryptionError($e);
                }
            } else {
                $splitToken->additionalInfo = $result['additional_info'];
            }
        } else {
            $splitToken->additionalInfo = null;
        }

        return $splitToken;
    }

    /**
     * Get the ID of the user the token belongs to.
     */
    public function getUserId(): ?int
    {
        return $this->userId;
    }

    /**
     * Get the expiration time of the token as timestamp.
     *
     * @return int|null Returns null if the token never expires
     */
    public function getExpirationTime(): ?int
    {
        return $this->expirationTime;
    }

    /**
     * Check if the token is eternal, i.e., never expires.
     *
     * @return bool True if the token never expires, false otherwise or if the token was revoked
     */
    public function isEternal(): bool
    {
        return $this->expirationTime === null;
    }

    /**
     * Get the expiration time of the token as a DateTime immutable object.
     *
     * @return DateTimeImmutable|null Returns the expiration time in the default time zone. If the token is eternal, returns null
     * @psalm-suppress PossiblyUnusedMethod
     */
    public function getExpirationDate(): ?DateTimeImmutable
    {
        if ($this->expirationTime === null) {
            return null;
        }

        return (new DateTimeImmutable(sprintf('@%s', $this->expirationTime)))
            ->setTimezone(new DateTimeZone(date_default_timezone_get()));
    }

    /**
     * Get the expiration time of the token in a given format.
     *
     * @param string $format A valid date format. Defaults to `'Y-m-d H:i:s'`
     *
     * @see https://www.php.net/manual/en/function.date.php
     *
     * @throws SplitTokenException if the date formatting fails
     * @return string|null         Returns the expiration time as date string in given format. If the token is eternal, returns null
     * @psalm-suppress PossiblyUnusedMethod
     */
    public function getExpirationDateFormatted(string $format = self::DEFAULT_EXPIRATION_DATE_FORMAT): ?string
    {
        if ($this->expirationTime === null) {
            return null;
        }

        try {
            return (new DateTimeImmutable(sprintf('@%s', $this->expirationTime)))
                ->setTimezone(new DateTimeZone(date_default_timezone_get()))
                ->format($format);
        } catch (Throwable $e) {
            throw new SplitTokenException(sprintf('Unable to format expiration date: %s.', $e->getMessage()), $e);
        }
    }

    /**
     * Check if the token is expired.
     *
     * @throws SplitTokenException if the expiration time is empty
     * @return bool                True if the token is expired, false otherwise
     *
     */
    public function isExpired(): bool
    {
        return null !== $this->expirationTime && $this->expirationTime <= time();
    }

    /**
     * Get the token type.
     *
     * @return int|null The token type or null if it was not set before
     */
    public function getTokenType(): ?int
    {
        return $this->tokenType;
    }

    /**
     * Get the additional info for the token.
     *
     * @return string|null The additional info or null if it was not set before
     */
    public function getAdditionalInfo(): ?string
    {
        return $this->additionalInfo;
    }

    /**
     * Store the token in the database.
     *
     * @throws InvalidTokenException If SQL error occurs
     * @throws SplitTokenException   if not enough data are provided
     * @return $this
     *
     */
    public function persist(): self
    {
        $sql = sprintf(
            'INSERT INTO %s (
                user_id, token_type, selector, verifier, additional_info, expiration_time
            ) VALUES (
                :userid, :tokentype, :selector, :verifier, :additional, :expires
            )',
            self::TABLE_NAME
        );
        $statement = $this->dbConnection->prepare($sql);

        if (!$statement) {
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
                ':expires' => $this->expirationTime,
            ]);
        } catch (PDOException $e) {
            throw InvalidTokenException::sqlError($e);
        }

        return $this;
    }

    /**
     * Revoke the token.
     *
     * @param bool $deleteToken If true, token is deleted. If false (default), it is expired
     *
     * @throws SplitTokenException
     * @return $this
     *
     */
    public function revokeToken(bool $deleteToken = false): self
    {
        $oneDayInSeconds = 86400;
        $this->expirationTime = time() - $oneDayInSeconds;

        if ($deleteToken) {
            $statement = $this->dbConnection->prepare(
                sprintf('DELETE FROM %s WHERE selector = :selector', self::TABLE_NAME)
            );

            if (!$statement) {
                $errorMessage = $this->dbConnection->errorInfo()[2] ?? 'Unknown PDO error';
                throw InvalidTokenException::pdoStatementError($errorMessage);
            }

            try {
                $statement->execute([':selector' => $this->selector]);
            } catch (PDOException $e) {
                throw InvalidTokenException::sqlError($e);
            }
        } else {
            $statement = $this->dbConnection->prepare(
                sprintf('UPDATE %s SET expiration_time = :expires WHERE selector = :selector', self::TABLE_NAME)
            );

            if (!$statement) {
                $errorMessage = $this->dbConnection->errorInfo()[2] ?? 'Unknown PDO error';
                throw InvalidTokenException::pdoStatementError($errorMessage);
            }

            try {
                $statement->execute([
                    ':expires' => $this->expirationTime,
                    ':selector' => $this->selector,
                ]);
            } catch (PDOException $e) {
                throw InvalidTokenException::sqlError($e);
            }
        }

        $this->token = null;
        $this->selector = null;
        $this->hashedVerifier = null;

        return $this;
    }

    /**
     * Delete all expired tokens from database.
     *
     * @param PDO $dbConnection Connection to the database
     *
     * @return int Returns the number of deleted tokens
     */
    public static function clearExpiredTokens(PDO $dbConnection): int
    {
        $statement = $dbConnection->prepare(sprintf('DELETE FROM %s WHERE expiration_time <= :time', self::TABLE_NAME));

        if (!$statement) {
            $errorMessage = $dbConnection->errorInfo()[2] ?? 'Unknown PDO error';
            throw InvalidTokenException::pdoStatementError($errorMessage);
        }

        try {
            $statement->execute([':time' => time()]);

            return $statement->rowCount();
        } catch (PDOException $e) {
            throw InvalidTokenException::sqlError($e);
        }
    }
}
