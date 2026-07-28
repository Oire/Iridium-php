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
use Oire\Iridium\Storage\ListableTokenStorageInterface;
use Oire\Iridium\Storage\TokenStorageInterface;
use Throwable;

/**
 * Iridium, a security library for hashing passwords, encrypting data and managing secure tokens
 * Implements the split token authentication model proposed by Paragon Initiatives.
 * Copyright © 2021-2026 André Polykanine, Oire Software, https://oire.org/
 * Idea Copyright © 2017 Paragon Initiatives.
 *
 * @see https://paragonie.com/blog/2017/02/split-tokens-token-based-authentication-protocols-without-side-channels
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
final class SplitToken
{
    public const string TABLE_NAME = 'iridium_tokens';
    public const string DEFAULT_EXPIRATION_DATE_FORMAT = 'Y-m-d H:i:s';
    public const string DEFAULT_EXPIRATION_TIME_OFFSET = '+1 hour';

    /**
     * Pass this as `$expirationTime` to get the default expiration, i.e., one hour from now.
     * It is the default value, and it is *not* the same as `null`, which means the token never
     * expires. Spelling it out beats the bare `0`, which reads like "no expiration" and silently
     * gives you an hour instead.
     */
    public const int EXPIRATION_DEFAULT = 0;

    /** How far into the past a revoked token's expiration is set. */
    public const int REVOCATION_TIME_OFFSET = 86400;
    private const int TOKEN_SIZE = 36;
    private const int SELECTOR_SIZE = 16;
    private const int VERIFIER_SIZE = 20;
    private ?string $token = null;
    private ?string $selector = null;
    private ?string $hashedVerifier = null;

    /**
     * Instantiate a new SplitToken object.
     *
     * @param TokenStorageInterface $storage        Storage backend for token persistence
     * @param int|null              $expirationTime expiration time of the token. Set to null if the token should not expire
     * @param int|null              $userId         The ID of the user in the database
     * @param int|null              $tokenType      A custom type for the token, most likely taken from an enum
     * @param string|null           $additionalInfo Some supplementary information attached to the token, like a JSON object
     *
     * @psalm-mutation-free
     */
    private function __construct(
        private TokenStorageInterface $storage,
        private ?int $expirationTime = null,
        private ?int $userId = null,
        private ?int $tokenType = null,
        private ?string $additionalInfo = null
    ) {}

    /**
     * Create a new split token.
     *
     * @param TokenStorageInterface $storage           Storage backend for token persistence
     * @param int|string|null       $expirationTime    expiration time of the token. Set to null if the token should not expire
     * @param int|null              $userId            The ID of the user in the database
     * @param int|null              $tokenType         A custom type for the token, most likely taken from an enum
     * @param string|null           $additionalInfo    Some supplementary information attached to the token, like a JSON object
     * @param SharedKey|null        $additionalInfoKey An Iridium key to encrypt the additional info or decrypt it if it was encrypted before
     *
     * @return self Returns a newly created SplitToken
     */
    public static function create(
        TokenStorageInterface $storage,
        int|string|null $expirationTime = self::EXPIRATION_DEFAULT,
        ?int $userId = null,
        ?int $tokenType = null,
        ?string $additionalInfo = null,
        ?SharedKey $additionalInfoKey = null
    ): self {
        $splitToken = new self($storage);
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
            : ($expirationTime === self::EXPIRATION_DEFAULT
                ? (new DateTimeImmutable(self::DEFAULT_EXPIRATION_TIME_OFFSET))->getTimestamp()
                : $expirationTime);

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
     * An expired token is rejected, and so is a revoked one, because revocation is stored as an
     * expiration in the past. Pass `$allowExpired = true` only when you want the object in order to
     * *report* on it — to tell a user when their password reset link died, say — never to
     * authenticate with it.
     *
     * @param string                $token             The token provided by the user
     * @param TokenStorageInterface $storage           Storage backend for token persistence
     * @param SharedKey|null        $additionalInfoKey If not empty, the encrypted additional info will be decrypted
     * @param bool                  $allowExpired      Return expired and revoked tokens instead of rejecting them
     *
     * @throws InvalidTokenException
     */
    public static function fromString(
        string $token,
        TokenStorageInterface $storage,
        ?SharedKey $additionalInfoKey = null,
        bool $allowExpired = false
    ): self {
        $splitToken = new self($storage);

        try {
            $rawToken = Base64::decode($token);
        } catch (Base64Exception $e) {
            throw InvalidTokenException::invalidTokenFormat($e->getMessage(), $e);
        }

        if (self::TOKEN_SIZE !== mb_strlen($rawToken, Crypt::STRING_ENCODING_8BIT)) {
            throw InvalidTokenException::invalidTokenLength();
        }

        $selector = Base64::encode(mb_substr($rawToken, 0, self::SELECTOR_SIZE, Crypt::STRING_ENCODING_8BIT));

        $result = $splitToken->storage->retrieve($selector);

        if ($result === false) {
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

        if (!$allowExpired && $splitToken->isExpired()) {
            throw InvalidTokenException::tokenExpired();
        }

        return $splitToken;
    }

    /**
     * Get the selector, i.e., the public half of the token used to look its record up.
     *
     * Needed by anything that acts on a stored token without holding its plaintext — listing a
     * user's tokens, revoking one from a management UI, recording its use.
     *
     * @return string|null Returns null if the token was revoked through this object
     */
    public function getSelector(): ?string
    {
        return $this->selector;
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
     *
     * @psalm-mutation-free
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
     * @return bool True if the token is expired, false otherwise
     */
    public function isExpired(): bool
    {
        return $this->expirationTime !== null && $this->expirationTime <= time();
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
     * @psalm-suppress MissingPureAnnotation
     */
    public function persist(): self
    {
        $this->storage->persist(
            selector: $this->selector ?? '',
            hashedVerifier: $this->hashedVerifier ?? '',
            userId: $this->userId,
            tokenType: $this->tokenType,
            additionalInfo: $this->additionalInfo,
            expirationTime: $this->expirationTime
        );

        return $this;
    }

    /**
     * Revoke the token.
     *
     * @param bool $deleteToken If true, token is deleted. If false (default), it is expired
     *
     * @throws SplitTokenException
     * @return $this
     */
    public function revokeToken(bool $deleteToken = false): self
    {
        self::revokeBySelector($this->storage, $this->selector ?? '', $deleteToken);

        $this->expirationTime = time() - self::REVOCATION_TIME_OFFSET;
        $this->token = null;
        $this->selector = null;
        $this->hashedVerifier = null;

        return $this;
    }

    /**
     * Revoke a token identified by its selector.
     *
     * This is the only revocation route open to a token whose plaintext nobody holds — which is
     * every long-lived token, since users are told the plaintext is shown once and never again.
     * {@see revokeToken()} needs an instance, and the only way to obtain one is
     * {@see fromString()}, which needs that plaintext.
     *
     * @param TokenStorageInterface $storage     Storage backend for token persistence
     * @param string                $selector    The selector of the token to revoke
     * @param bool                  $deleteToken If true, the token row is deleted. If false (default), it is expired
     *
     * @throws InvalidTokenException
     */
    public static function revokeBySelector(TokenStorageInterface $storage, string $selector, bool $deleteToken = false): void
    {
        if ($deleteToken) {
            $storage->delete($selector);

            return;
        }

        $storage->updateExpiration($selector, time() - self::REVOCATION_TIME_OFFSET);
    }

    /**
     * Delete all expired tokens from storage.
     *
     * **This deletes revoked tokens too**, because revocation is stored as an expiration in the
     * past — so running it erases the record of what was revoked and when. Where that history
     * matters, use {@see ListableTokenStorageInterface::clearExpiredBefore()} with a cutoff instead,
     * which sweeps only what expired long enough ago to be uninteresting.
     *
     * @param TokenStorageInterface $storage Storage backend for token persistence
     *
     * @return int Returns the number of deleted tokens
     *
     * @psalm-suppress MissingPureAnnotation
     */
    public static function clearExpiredTokens(TokenStorageInterface $storage): int
    {
        return $storage->clearExpired();
    }
}
