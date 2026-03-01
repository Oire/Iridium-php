<?php

declare(strict_types=1);

namespace Oire\Iridium\Tests;

use Oire\Iridium\SplitToken;
use Oire\Iridium\Storage\PdoTokenStorage;
use Override;
use PDO;
use PHPUnit\Framework\TestCase;

/**
 * Iridium, a security library for hashing passwords, encrypting data and managing secure tokens
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
final class PdoTokenStorageTest extends TestCase
{
    private static ?PDO $db = null;
    private static ?PdoTokenStorage $storage = null;

    private static function getStorage(): PdoTokenStorage
    {
        if (self::$storage === null) {
            self::fail('Storage is not initialized.');
        }

        return self::$storage;
    }

    #[Override]
    public static function setUpBeforeClass(): void
    {
        $host = $_ENV['DB_HOST'] ?? 'mariadb';
        $port = $_ENV['DB_PORT'] ?? '3306';
        $database = $_ENV['DB_DATABASE'] ?? 'iridium_test';
        $username = $_ENV['DB_USERNAME'] ?? 'iridium';
        $password = $_ENV['DB_PASSWORD'] ?? 'iridium_secret';

        $dsn = sprintf('mysql:host=%s;port=%s;dbname=%s;charset=utf8mb4', $host, $port, $database);
        self::$db = new PDO($dsn, $username, $password);
        self::$storage = new PdoTokenStorage(self::$db);

        $schema = file_get_contents(__DIR__ . '/schema.sql');
        self::$db->exec(sprintf('DROP TABLE IF EXISTS %s', SplitToken::TABLE_NAME));
        /** @psalm-suppress PossiblyFalseArgument */
        self::$db->exec($schema);
    }

    /** @psalm-suppress MissingPureAnnotation */
    #[Override]
    protected function setUp(): void
    {
        /** @psalm-suppress PossiblyNullReference */
        self::$db->exec(sprintf('TRUNCATE TABLE %s', SplitToken::TABLE_NAME));
    }

    /** @psalm-suppress MissingPureAnnotation */
    #[Override]
    public static function tearDownAfterClass(): void
    {
        self::$storage = null;
        self::$db = null;
    }

    public function testPersistAndRetrieve(): void
    {
        $storage = self::getStorage();
        $selector = 'test_selector_1';
        $verifier = 'test_verifier_1';
        $userId = 42;
        $tokenType = 1;
        $additionalInfo = '{"key":"value"}';
        $expirationTime = time() + 3600;

        $storage->persist($selector, $verifier, $userId, $tokenType, $additionalInfo, $expirationTime);

        $result = $storage->retrieve($selector);

        self::assertIsArray($result);
        self::assertSame($selector, $result['selector']);
        self::assertSame($verifier, $result['verifier']);
        self::assertSame($userId, (int) $result['user_id']);
        self::assertSame($tokenType, (int) $result['token_type']);
        self::assertSame($additionalInfo, $result['additional_info']);
        self::assertSame($expirationTime, (int) $result['expiration_time']);
    }

    public function testRetrieveNonExistent(): void
    {
        $storage = self::getStorage();

        $result = $storage->retrieve('nonexistent_selector');

        self::assertFalse($result);
    }

    public function testUpdateExpiration(): void
    {
        $storage = self::getStorage();
        $selector = 'test_selector_2';
        $expirationTime = time() + 3600;
        $newExpirationTime = time() - 86400;

        $storage->persist($selector, 'verifier_2', 1, null, null, $expirationTime);
        $storage->updateExpiration($selector, $newExpirationTime);

        $result = $storage->retrieve($selector);

        self::assertIsArray($result);
        self::assertSame($newExpirationTime, (int) $result['expiration_time']);
    }

    public function testDelete(): void
    {
        $storage = self::getStorage();
        $selector = 'test_selector_3';

        $storage->persist($selector, 'verifier_3', 1, null, null, time() + 3600);
        $storage->delete($selector);

        $result = $storage->retrieve($selector);

        self::assertFalse($result);
    }

    public function testClearExpired(): void
    {
        $storage = self::getStorage();

        // One expired token
        $storage->persist('expired_1', 'verifier_e1', 1, null, null, time() - 3600);
        // One expired token
        $storage->persist('expired_2', 'verifier_e2', 2, null, null, time() - 1800);
        // One valid token
        $storage->persist('valid_1', 'verifier_v1', 3, null, null, time() + 3600);

        $deleted = $storage->clearExpired();

        self::assertSame(2, $deleted);

        // Valid token should still exist
        $result = $storage->retrieve('valid_1');
        self::assertIsArray($result);

        // Expired tokens should be gone
        self::assertFalse($storage->retrieve('expired_1'));
        self::assertFalse($storage->retrieve('expired_2'));
    }
}
