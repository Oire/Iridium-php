<?php

declare(strict_types=1);

namespace Oire\Iridium\Storage;

use DateTimeImmutable;

/**
 * Iridium, a security library for hashing passwords, encrypting data and managing secure tokens
 * One persisted token row, as returned by ListableTokenStorageInterface.
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
 * Deliberately carries no verifier and no token: a listing is something you show a user, and
 * neither of those halves belongs on a screen.
 */
final readonly class StoredToken
{
    /** @psalm-mutation-free */
    public function __construct(
        public int $id,
        public ?int $userId,
        public string $selector,
        public ?int $tokenType,
        public ?string $additionalInfo,
        public ?int $expirationTime,
        public ?DateTimeImmutable $createdAt = null,
        public ?DateTimeImmutable $lastUsedAt = null,
    ) {}

    /**
     * The token never expires.
     *
     * @psalm-mutation-free
     */
    public function isEternal(): bool
    {
        return $this->expirationTime === null;
    }

    /**
     * The token is expired. Note that a revoked token is also reported as expired, since revocation
     * is stored as an expiration in the past.
     */
    public function isExpired(): bool
    {
        return $this->expirationTime !== null && $this->expirationTime <= time();
    }

    /** @return DateTimeImmutable|null Null if the token is eternal */
    public function getExpirationDate(): ?DateTimeImmutable
    {
        return $this->expirationTime === null
            ? null
            : new DateTimeImmutable(sprintf('@%d', $this->expirationTime));
    }
}
