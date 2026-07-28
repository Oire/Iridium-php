<?php

declare(strict_types=1);

namespace Oire\Iridium\Storage;

use DateTimeImmutable;
use Oire\Iridium\Exception\InvalidTokenException;
use Override;
use PDO;
use PDOException;
use PDOStatement;

/**
 * Iridium, a security library for hashing passwords, encrypting data and managing secure tokens
 * PDO-based storage implementation for split tokens.
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
final class PdoTokenStorage implements ListableTokenStorageInterface
{
    public function __construct(
        private PDO $dbConnection,
        private string $tableName = 'iridium_tokens'
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

    #[Override]
    public function persist(
        string $selector,
        string $hashedVerifier,
        ?int $userId,
        ?int $tokenType,
        ?string $additionalInfo,
        ?int $expirationTime
    ): void {
        $sql = sprintf(
            'INSERT INTO %s (
                user_id, token_type, selector, verifier, additional_info, expiration_time
            ) VALUES (
                :userid, :tokentype, :selector, :verifier, :additional, :expires
            )',
            $this->tableName
        );
        $statement = $this->dbConnection->prepare($sql);

        if (!$statement) {
            /** @var string $errorMessage */
            $errorMessage = $this->dbConnection->errorInfo()[2] ?? 'Unknown PDO error';
            throw InvalidTokenException::pdoStatementError($errorMessage);
        }

        try {
            $statement->execute([
                ':userid' => $userId,
                ':tokentype' => $tokenType,
                ':selector' => $selector,
                ':verifier' => $hashedVerifier,
                ':additional' => $additionalInfo,
                ':expires' => $expirationTime,
            ]);
        } catch (PDOException $e) {
            throw InvalidTokenException::sqlError($e);
        }
    }

    /** @return array<string, string|null>|false */
    #[Override]
    public function retrieve(string $selector): array|false
    {
        $sql = sprintf(
            'SELECT
                user_id, token_type, selector, verifier, additional_info, expiration_time
                FROM %s
                WHERE selector = :selector',
            $this->tableName
        );
        $statement = $this->dbConnection->prepare($sql);

        if (!$statement) {
            /** @var string $errorMessage */
            $errorMessage = $this->dbConnection->errorInfo()[2] ?? 'Unknown PDO error';
            throw InvalidTokenException::pdoStatementError($errorMessage);
        }

        try {
            $statement->execute([':selector' => $selector]);
        } catch (PDOException $e) {
            throw InvalidTokenException::sqlError($e);
        }

        /** @var array<string, string|null>|false */
        return $statement->fetch();
    }

    #[Override]
    public function updateExpiration(string $selector, int $expirationTime): void
    {
        $sql = sprintf(
            'UPDATE %s SET expiration_time = :expires WHERE selector = :selector',
            $this->tableName
        );
        $statement = $this->dbConnection->prepare($sql);

        if (!$statement) {
            /** @var string $errorMessage */
            $errorMessage = $this->dbConnection->errorInfo()[2] ?? 'Unknown PDO error';
            throw InvalidTokenException::pdoStatementError($errorMessage);
        }

        try {
            $statement->execute([
                ':expires' => $expirationTime,
                ':selector' => $selector,
            ]);
        } catch (PDOException $e) {
            throw InvalidTokenException::sqlError($e);
        }
    }

    #[Override]
    public function delete(string $selector): void
    {
        $sql = sprintf('DELETE FROM %s WHERE selector = :selector', $this->tableName);
        $statement = $this->dbConnection->prepare($sql);

        if (!$statement) {
            /** @var string $errorMessage */
            $errorMessage = $this->dbConnection->errorInfo()[2] ?? 'Unknown PDO error';
            throw InvalidTokenException::pdoStatementError($errorMessage);
        }

        try {
            $statement->execute([':selector' => $selector]);
        } catch (PDOException $e) {
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
        $sql = sprintf('DELETE FROM %s WHERE expiration_time <= :time', $this->tableName);
        $statement = $this->prepare($sql);

        try {
            $statement->execute([':time' => $expiredBefore]);

            return $statement->rowCount();
        } catch (PDOException $e) {
            throw InvalidTokenException::sqlError($e);
        }
    }

    /** @return list<StoredToken> */
    #[Override]
    public function findByUserId(int $userId): array
    {
        $sql = sprintf('SELECT * FROM %s WHERE user_id = :userid ORDER BY id ASC', $this->tableName);
        $statement = $this->prepare($sql);

        try {
            $statement->execute([':userid' => $userId]);
        } catch (PDOException $e) {
            throw InvalidTokenException::sqlError($e);
        }

        /** @var list<array<string, mixed>> $rows */
        $rows = $statement->fetchAll();

        return array_map($this->hydrate(...), $rows);
    }

    #[Override]
    public function findBySelector(string $selector): ?StoredToken
    {
        $sql = sprintf('SELECT * FROM %s WHERE selector = :selector', $this->tableName);
        $statement = $this->prepare($sql);

        try {
            $statement->execute([':selector' => $selector]);
        } catch (PDOException $e) {
            throw InvalidTokenException::sqlError($e);
        }

        /** @var array<string, mixed>|false $row */
        $row = $statement->fetch();

        return $row === false ? null : $this->hydrate($row);
    }

    #[Override]
    public function touch(string $selector, int $usedAt): void
    {
        $sql = sprintf('UPDATE %s SET last_used_at = :usedat WHERE selector = :selector', $this->tableName);
        $statement = $this->prepare($sql);

        try {
            $statement->execute([
                ':usedat' => (new DateTimeImmutable(sprintf('@%d', $usedAt)))->format('Y-m-d H:i:s'),
                ':selector' => $selector,
            ]);
        } catch (PDOException $e) {
            throw InvalidTokenException::sqlError($e);
        }
    }

    /** @throws InvalidTokenException */
    private function prepare(string $sql): PDOStatement
    {
        $statement = $this->dbConnection->prepare($sql);

        if (!$statement) {
            /** @var string $errorMessage */
            $errorMessage = $this->dbConnection->errorInfo()[2] ?? 'Unknown PDO error';
            throw InvalidTokenException::pdoStatementError($errorMessage);
        }

        return $statement;
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
