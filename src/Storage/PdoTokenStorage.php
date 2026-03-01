<?php

declare(strict_types=1);

namespace Oire\Iridium\Storage;

use Oire\Iridium\Exception\InvalidTokenException;
use Override;
use PDO;
use PDOException;

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
final class PdoTokenStorage implements TokenStorageInterface
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
        $sql = sprintf('DELETE FROM %s WHERE expiration_time <= :time', $this->tableName);
        $statement = $this->dbConnection->prepare($sql);

        if (!$statement) {
            /** @var string $errorMessage */
            $errorMessage = $this->dbConnection->errorInfo()[2] ?? 'Unknown PDO error';
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
