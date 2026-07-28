<?php

declare(strict_types=1);

namespace Oire\Iridium\Storage;

use Oire\Iridium\Exception\InvalidTokenException;

/**
 * Iridium, a security library for hashing passwords, encrypting data and managing secure tokens
 * Optional storage extension for enumerating and maintaining stored tokens.
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
 *
 * `TokenStorageInterface` can persist, retrieve one token by selector, expire, delete and sweep.
 * That is enough for one-shot tokens such as password resets, and not enough for long-lived
 * personal access tokens, where a user has to be able to see what they issued and revoke one of it.
 *
 * Kept separate rather than folded into `TokenStorageInterface` so that existing implementations
 * keep working untouched, and because the two extra columns below are only needed by those who
 * want these features.
 *
 * **Schema note.** `findByUserId()` and `findBySelector()` also read `created_at`, and `touch()`
 * writes `last_used_at`. Add both to your token table before implementing this interface:
 *
 * ```sql
 * ALTER TABLE iridium_tokens
 *     ADD COLUMN created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 *     ADD COLUMN last_used_at TIMESTAMP NULL;
 * ```
 */
/** @psalm-mutable */
interface ListableTokenStorageInterface extends TokenStorageInterface
{
    /**
     * Find every token belonging to a user, oldest first.
     *
     * @param int $userId The ID of the user
     *
     * @throws InvalidTokenException
     * @return list<StoredToken>
     *
     * @psalm-impure
     */
    public function findByUserId(int $userId): array;

    /**
     * Find one token by its selector, without validating any verifier.
     *
     * Unlike `retrieve()`, which exists to feed `SplitToken::fromString()`, this returns a value
     * object suitable for display and for administrative action.
     *
     * @param string $selector The token selector
     *
     * @throws InvalidTokenException
     *
     * @psalm-impure
     */
    public function findBySelector(string $selector): ?StoredToken;

    /**
     * Record that a token was used.
     *
     * Callers are expected to throttle this themselves: a chatty API client would otherwise force
     * a write on every single request.
     *
     * @param string $selector The token selector
     * @param int    $usedAt   Timestamp of the use
     *
     * @throws InvalidTokenException
     *
     * @psalm-impure
     */
    public function touch(string $selector, int $usedAt): void;

    /**
     * Delete tokens that expired at or before the given timestamp.
     *
     * The cutoff is what makes this different from `clearExpired()`, which takes the current time
     * and therefore also erases tokens revoked seconds ago — revocation being stored as an
     * expiration in the past. Passing, say, `time() - 90 * 86400` sweeps the genuinely stale rows
     * while leaving a quarter of revocation history in place to audit.
     *
     * @param int $expiredBefore Delete tokens whose expiration is at or before this timestamp
     *
     * @throws InvalidTokenException
     * @return int                   The number of deleted tokens
     *
     * @psalm-impure
     */
    public function clearExpiredBefore(int $expiredBefore): int;
}
