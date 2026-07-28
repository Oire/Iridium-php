<?php

declare(strict_types=1);

namespace Oire\Iridium\Tests;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Oire\Iridium\SplitToken;
use Oire\Iridium\Storage\DoctrineDbalTokenStorage;
use Override;
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
final class DoctrineDbalTokenStorageTest extends TestCase
{
    private const int TEST_USER_ID = 12345;
    private static ?Connection $connection = null;
    private static ?DoctrineDbalTokenStorage $storage = null;

    private static function getStorage(): DoctrineDbalTokenStorage
    {
        if (self::$storage === null) {
            self::fail('Storage is not initialized.');
        }

        return self::$storage;
    }

    private static function getConnection(): Connection
    {
        if (self::$connection === null) {
            self::fail('Connection is not initialized.');
        }

        return self::$connection;
    }

    #[Override]
    public static function setUpBeforeClass(): void
    {
        self::$connection = DriverManager::getConnection([
            'driver' => 'pdo_mysql',
            'host' => $_ENV['DB_HOST'] ?? 'mariadb',
            'port' => (int) ($_ENV['DB_PORT'] ?? 3306),
            'dbname' => $_ENV['DB_DATABASE'] ?? 'iridium_test',
            'user' => $_ENV['DB_USERNAME'] ?? 'iridium',
            'password' => $_ENV['DB_PASSWORD'] ?? 'iridium_secret',
            'charset' => 'utf8mb4',
        ]);
        self::$storage = new DoctrineDbalTokenStorage(self::$connection);

        $schema = file_get_contents(__DIR__ . '/schema.sql');
        self::$connection->executeStatement(sprintf('DROP TABLE IF EXISTS %s', SplitToken::TABLE_NAME));
        /** @psalm-suppress PossiblyFalseArgument */
        self::$connection->executeStatement($schema);
    }

    #[Override]
    protected function setUp(): void
    {
        self::getConnection()->executeStatement(sprintf('TRUNCATE TABLE %s', SplitToken::TABLE_NAME));
    }

    /** @psalm-suppress MissingPureAnnotation */
    #[Override]
    public static function tearDownAfterClass(): void
    {
        self::$storage = null;
        self::$connection = null;
    }

    /**
     * The key names are the contract: `SplitToken::fromString()` indexes the returned row by
     * `verifier`, `user_id`, `expiration_time`, `token_type` and `additional_info`.
     */
    public function testPersistAndRetrieve(): void
    {
        $storage = self::getStorage();
        $storage->persist('test-selector', 'test-verifier', self::TEST_USER_ID, 3, 'info', 1893456000);

        $row = $storage->retrieve('test-selector');

        self::assertIsArray($row);
        self::assertSame('test-verifier', $row['verifier']);
        self::assertSame((string) self::TEST_USER_ID, $row['user_id']);
        self::assertSame('3', $row['token_type']);
        self::assertSame('info', $row['additional_info']);
        self::assertSame('1893456000', $row['expiration_time']);
    }

    public function testRetrieveUnknownSelector(): void
    {
        self::assertFalse(self::getStorage()->retrieve('nonexistent'));
    }

    public function testNullableColumnsRoundTrip(): void
    {
        $storage = self::getStorage();
        $storage->persist('nulls', 'verifier', null, null, null, null);

        $row = $storage->retrieve('nulls');

        self::assertIsArray($row);
        self::assertNull($row['user_id']);
        self::assertNull($row['token_type']);
        self::assertNull($row['additional_info']);
        self::assertNull($row['expiration_time']);
    }

    public function testUpdateExpirationAndDelete(): void
    {
        $storage = self::getStorage();
        $storage->persist('mutable', 'verifier', self::TEST_USER_ID, null, null, null);

        $storage->updateExpiration('mutable', 42);
        $row = $storage->retrieve('mutable');

        self::assertIsArray($row);
        self::assertSame('42', $row['expiration_time']);

        $storage->delete('mutable');

        self::assertFalse($storage->retrieve('mutable'));
    }

    public function testClearExpired(): void
    {
        $storage = self::getStorage();
        $storage->persist('past', 'v1', 1, null, null, time() - 10);
        $storage->persist('future', 'v2', 2, null, null, time() + 3600);
        $storage->persist('eternal', 'v3', 3, null, null, null);

        self::assertSame(1, $storage->clearExpired());
        self::assertFalse($storage->retrieve('past'));
        self::assertIsArray($storage->retrieve('future'));
        self::assertIsArray($storage->retrieve('eternal'), 'An eternal token must never be swept.');
    }

    /** The whole point of the cutoff: keep recent revocations readable. */
    public function testClearExpiredBeforeKeepsRecentRevocations(): void
    {
        $storage = self::getStorage();
        $storage->persist('ancient', 'v1', 1, null, null, time() - 100 * 86400);
        $storage->persist('recent', 'v2', 2, null, null, time() - 86400);

        self::assertSame(1, $storage->clearExpiredBefore(time() - 90 * 86400));
        self::assertFalse($storage->retrieve('ancient'));
        self::assertIsArray($storage->retrieve('recent'));
    }

    public function testFindByUserIdIsScopedAndOrdered(): void
    {
        $storage = self::getStorage();
        $storage->persist('mine-1', 'v1', self::TEST_USER_ID, null, 'First', null);
        $storage->persist('theirs', 'v2', 999, null, 'Not mine', null);
        $storage->persist('mine-2', 'v3', self::TEST_USER_ID, null, 'Second', null);

        $found = $storage->findByUserId(self::TEST_USER_ID);

        self::assertCount(2, $found);
        self::assertSame(['First', 'Second'], array_map(static fn($token): ?string => $token->additionalInfo, $found));
        self::assertSame(['mine-1', 'mine-2'], array_map(static fn($token): string => $token->selector, $found));
        self::assertSame([true, true], array_map(static fn($token): bool => $token->id > 0, $found));
        self::assertSame([true, true], array_map(static fn($token): bool => $token->createdAt !== null, $found));
        self::assertSame([true, true], array_map(static fn($token): bool => $token->lastUsedAt === null, $found));
    }

    public function testFindBySelector(): void
    {
        $storage = self::getStorage();
        $storage->persist('lookup', 'verifier', self::TEST_USER_ID, 7, 'Labeled', null);

        $found = $storage->findBySelector('lookup');

        self::assertNotNull($found);
        self::assertSame(self::TEST_USER_ID, $found->userId);
        self::assertSame(7, $found->tokenType);
        self::assertSame('Labeled', $found->additionalInfo);
        self::assertTrue($found->isEternal());
        self::assertFalse($found->isExpired());
        self::assertNull($found->getExpirationDate());
        self::assertNull($storage->findBySelector('nope'));
    }

    public function testFindBySelectorReportsARevokedTokenAsExpired(): void
    {
        $storage = self::getStorage();
        $storage->persist('revoked', 'verifier', self::TEST_USER_ID, null, null, null);

        SplitToken::revokeBySelector($storage, 'revoked');
        $found = $storage->findBySelector('revoked');

        self::assertNotNull($found);
        self::assertTrue($found->isExpired());
        self::assertFalse($found->isEternal());
        self::assertNotNull($found->getExpirationDate());
    }

    public function testTouch(): void
    {
        $storage = self::getStorage();
        $storage->persist('used', 'verifier', self::TEST_USER_ID, null, null, null);

        $usedAt = time();
        $storage->touch('used', $usedAt);
        $found = $storage->findBySelector('used');

        self::assertNotNull($found);
        self::assertNotNull($found->lastUsedAt);
        self::assertSame($usedAt, $found->lastUsedAt->getTimestamp());
    }

    /** A full round trip through SplitToken, to prove the storage satisfies its real consumer. */
    public function testSplitTokenRoundTripThroughThisStorage(): void
    {
        $storage = self::getStorage();
        $created = SplitToken::create(
            storage: $storage,
            expirationTime: null,
            userId: self::TEST_USER_ID,
            additionalInfo: 'Agent token'
        )
            ->persist();
        $token = $created->getToken();

        self::assertNotNull($token);

        $resolved = SplitToken::fromString($token, $storage);

        self::assertSame(self::TEST_USER_ID, $resolved->getUserId());
        self::assertSame('Agent token', $resolved->getAdditionalInfo());
        self::assertSame($created->getSelector(), $resolved->getSelector());
        self::assertTrue($resolved->isEternal());
    }
}
