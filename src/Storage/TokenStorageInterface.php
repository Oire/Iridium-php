<?php

declare(strict_types=1);

namespace Oire\Iridium\Storage;

use Oire\Iridium\Exception\InvalidTokenException;

/**
 * Iridium, a security library for hashing passwords, encrypting data and managing secure tokens
 * Storage interface for split token persistence.
 * Copyright © 2021-2026 André Polykanine, Oire Software, https://oire.org/
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
/** @psalm-mutable */
interface TokenStorageInterface
{
    /**
     * Persist a token to storage.
     *
     * @param string      $selector       The token selector
     * @param string      $hashedVerifier The hashed verifier
     * @param int|null    $userId         The user ID
     * @param int|null    $tokenType      The token type
     * @param string|null $additionalInfo Additional information
     * @param int|null    $expirationTime Expiration timestamp
     *
     * @throws InvalidTokenException
     *
     * @psalm-impure
     */
    public function persist(
        string $selector,
        string $hashedVerifier,
        ?int $userId,
        ?int $tokenType,
        ?string $additionalInfo,
        ?int $expirationTime
    ): void;

    /**
     * Retrieve a token record by selector.
     *
     * @param string $selector The token selector
     *
     * @throws InvalidTokenException
     * @return array<string, string|null>|false The token record or false if not found
     *
     * @psalm-impure
     */
    public function retrieve(string $selector): array|false;

    /**
     * Update the expiration time for a token.
     *
     * @param string $selector       The token selector
     * @param int    $expirationTime New expiration timestamp
     *
     * @throws InvalidTokenException
     *
     * @psalm-impure
     */
    public function updateExpiration(string $selector, int $expirationTime): void;

    /**
     * Delete a token by selector.
     *
     * @param string $selector The token selector
     *
     * @throws InvalidTokenException
     *
     * @psalm-impure
     */
    public function delete(string $selector): void;

    /**
     * Clear all expired tokens.
     *
     * @throws InvalidTokenException
     * @return int                   The number of deleted tokens
     *
     * @psalm-impure
     */
    public function clearExpired(): int;
}
