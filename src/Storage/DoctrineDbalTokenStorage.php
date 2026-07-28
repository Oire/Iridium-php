<?php

declare(strict_types=1);

namespace Oire\Iridium\Storage;

use DateTimeImmutable;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Exception as DbalException;
use Oire\Iridium\Exception\InvalidTokenException;
use Override;

/**
 * Iridium, a security library for hashing passwords, encrypting data and managing secure tokens
 * Doctrine DBAL storage implementation for split tokens.
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
 * `doctrine/dbal` is a development and suggested dependency only, so the library itself stays
 * dependency-free. Instantiate this class from an ORM consumer with
 * `new DoctrineDbalTokenStorage($entityManager->getConnection())`.
 */
final class DoctrineDbalTokenStorage implements ListableTokenStorageInterface
{
    /** @psalm-mutation-free */
    public function __construct(
        private readonly Connection $dbConnection,
        private readonly string $tableName = 'iridium_tokens'
    ) {}

    #[Override]
    public function persist(
        string $selector,
        string $hashedVerifier,
        ?int $userId,
        ?int $tokenType,
        ?string $additionalInfo,
        ?int $expirationTime
    ): void {
        try {
            $this->dbConnection->insert($this->tableName, [
                'user_id' => $userId,
                'token_type' => $tokenType,
                'selector' => $selector,
                'verifier' => $hashedVerifier,
                'additional_info' => $additionalInfo,
                'expiration_time' => $expirationTime,
            ]);
        } catch (DbalException $e) {
            throw InvalidTokenException::sqlError($e);
        }
    }

    /** @return array<string, string|null>|false */
    #[Override]
    public function retrieve(string $selector): array|false
    {
        try {
            $row = $this->dbConnection->fetchAssociative(
                sprintf(
                    'SELECT user_id, token_type, selector, verifier, additional_info, expiration_time FROM %s WHERE selector = ?',
                    $this->tableName
                ),
                [$selector]
            );
        } catch (DbalException $e) {
            throw InvalidTokenException::sqlError($e);
        }

        if ($row === false) {
            return false;
        }

        // SplitToken compares and casts these as strings or nulls, never as integers.
        return array_map(
            static fn(mixed $value): ?string => $value === null ? null : (string) $value,
            $row
        );
    }

    #[Override]
    public function updateExpiration(string $selector, int $expirationTime): void
    {
        try {
            $this->dbConnection->update(
                $this->tableName,
                ['expiration_time' => $expirationTime],
                ['selector' => $selector]
            );
        } catch (DbalException $e) {
            throw InvalidTokenException::sqlError($e);
        }
    }

    #[Override]
    public function delete(string $selector): void
    {
        try {
            $this->dbConnection->delete($this->tableName, ['selector' => $selector]);
        } catch (DbalException $e) {
            throw InvalidTokenException::sqlError($e);
        }
    }

    #[Override]
    public function clearExpired(): int
    {
        return $this->clearExpiredBefore(time());
    }

    #[Override]
    public function clearExpiredBefore(int $expiredBefore): int
    {
        try {
            return (int) $this->dbConnection->executeStatement(
                sprintf('DELETE FROM %s WHERE expiration_time <= ?', $this->tableName),
                [$expiredBefore]
            );
        } catch (DbalException $e) {
            throw InvalidTokenException::sqlError($e);
        }
    }

    /** @return list<StoredToken> */
    #[Override]
    public function findByUserId(int $userId): array
    {
        try {
            $rows = $this->dbConnection->fetchAllAssociative(
                sprintf('SELECT * FROM %s WHERE user_id = ? ORDER BY id ASC', $this->tableName),
                [$userId]
            );
        } catch (DbalException $e) {
            throw InvalidTokenException::sqlError($e);
        }

        return array_map($this->hydrate(...), $rows);
    }

    #[Override]
    public function findBySelector(string $selector): ?StoredToken
    {
        try {
            $row = $this->dbConnection->fetchAssociative(
                sprintf('SELECT * FROM %s WHERE selector = ?', $this->tableName),
                [$selector]
            );
        } catch (DbalException $e) {
            throw InvalidTokenException::sqlError($e);
        }

        return $row === false ? null : $this->hydrate($row);
    }

    #[Override]
    public function touch(string $selector, int $usedAt): void
    {
        try {
            $this->dbConnection->update(
                $this->tableName,
                ['last_used_at' => (new DateTimeImmutable(sprintf('@%d', $usedAt)))->format('Y-m-d H:i:s')],
                ['selector' => $selector]
            );
        } catch (DbalException $e) {
            throw InvalidTokenException::sqlError($e);
        }
    }

    /** @param array<string, mixed> $row */
    private function hydrate(array $row): StoredToken
    {
        /** @var array{id: mixed, user_id: mixed, selector: mixed, token_type: mixed, additional_info: mixed, expiration_time: mixed, created_at?: mixed, last_used_at?: mixed} $row */
        return new StoredToken(
            id: (int) $row['id'],
            userId: $row['user_id'] === null ? null : (int) $row['user_id'],
            selector: (string) $row['selector'],
            tokenType: $row['token_type'] === null ? null : (int) $row['token_type'],
            additionalInfo: $row['additional_info'] === null ? null : (string) $row['additional_info'],
            expirationTime: $row['expiration_time'] === null ? null : (int) $row['expiration_time'],
            createdAt: self::toDateTime($row['created_at'] ?? null),
            lastUsedAt: self::toDateTime($row['last_used_at'] ?? null),
        );
    }

    /** @psalm-suppress RiskyTruthyFalsyComparison */
    private static function toDateTime(mixed $value): ?DateTimeImmutable
    {
        if ($value === null || $value === '') {
            return null;
        }

        return new DateTimeImmutable((string) $value);
    }
}
