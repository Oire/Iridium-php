<?php

declare(strict_types=1);

namespace Oire\Iridium\Tests;

use DateTimeImmutable;
use Oire\Iridium\Exception\InvalidTokenException;
use Oire\Iridium\Exception\SplitTokenException;
use Oire\Iridium\Key\SharedKey;
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
final class SplitTokenTest extends TestCase
{
    // Oire\Iridium\Base64::encode(hex2bin('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324'));
    private const string TEST_TOKEN = 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMk';
    private const string TEST_SELECTOR = 'AQIDBAUGBwgJCgsMDQ4PEA';
    private const string TEST_VERIFIER = 'ERITFBUWFxgZGhscHR4fICEiIyQ';
    private const string TEST_HASHED_VERIFIER = 'UTYMVAte1GIu5QtgTAgjJ_Nb0R8ys_O-WdDbTMZPUbncmjA-hOJGZNM1aNedoBEH';
    private const int TEST_USER_ID = 12345;
    private const int TEST_TOKEN_TYPE = 3;
    private const string TEST_ADDITIONAL_INFO = '{"oldEmail":"test@example.com","newEmail":"john.doe@example.com"}';
    private const string TEST_KEY = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';
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

    public function testSetTokenFromUserProvidedString(): void
    {
        $storage = self::getStorage();
        $expirationTime = (new DateTimeImmutable(SplitToken::DEFAULT_EXPIRATION_TIME_OFFSET))->getTimestamp();

        $storage->persist(
            self::TEST_SELECTOR,
            self::TEST_HASHED_VERIFIER,
            self::TEST_USER_ID,
            self::TEST_TOKEN_TYPE,
            self::TEST_ADDITIONAL_INFO,
            $expirationTime
        );

        $splittoken = SplitToken::fromString(self::TEST_TOKEN, $storage);

        self::assertSame(self::TEST_TOKEN, $splittoken->getToken());
        self::assertSame(self::TEST_USER_ID, $splittoken->getUserId());
        self::assertSame(self::TEST_TOKEN_TYPE, $splittoken->getTokenType());
        self::assertSame($expirationTime, $splittoken->getExpirationTime());
        self::assertSame(self::TEST_ADDITIONAL_INFO, $splittoken->getAdditionalInfo());
    }

    public function testCreateToken(): void
    {
        $storage = self::getStorage();
        $expirationTime = time() + 10800;
        $startSplitToken = SplitToken::create(
            storage: $storage,
            expirationTime: $expirationTime,
            userId: self::TEST_USER_ID,
            tokenType: null,
            additionalInfo: self::TEST_ADDITIONAL_INFO
        )
            ->persist();
        $token = $startSplitToken->getToken();

        /** @psalm-suppress PossiblyNullArgument */
        $splittoken = SplitToken::fromString($token, $storage);

        self::assertSame($token, $splittoken->getToken());
        self::assertSame(self::TEST_USER_ID, $splittoken->getUserId());
        self::assertSame($expirationTime, $splittoken->getExpirationTime());
        self::assertFalse($splittoken->isEternal());
        self::assertNull($splittoken->getTokenType());
        self::assertSame(self::TEST_ADDITIONAL_INFO, $splittoken->getAdditionalInfo());
    }

    public function testCreateEternalToken(): void
    {
        $storage = self::getStorage();
        $startSplittoken = SplitToken::create($storage, null)->persist();
        $token = $startSplittoken->getToken();
        /** @psalm-suppress PossiblyNullArgument */
        $splittoken = SplitToken::fromString($token, $storage);

        self::assertSame($token, $splittoken->getToken());
        self::assertNull($splittoken->getUserId());
        self::assertNull($splittoken->getExpirationTime());
        self::assertTrue($splittoken->isEternal());
        self::assertNull($splittoken->getTokenType());
        self::assertNull($splittoken->getAdditionalInfo());
    }

    public function testSetDefaultExpirationTime(): void
    {
        $storage = self::getStorage();
        $startSplitToken = SplitToken::create($storage)->persist();
        $token = $startSplitToken->getToken();
        /** @psalm-suppress PossiblyNullArgument */
        $splitToken = SplitToken::fromString($token, $storage);

        self::assertSame($token, $splitToken->getToken());
        self::assertNotNull($splitToken->getExpirationTime());
        self::assertGreaterThan(time(), $splitToken->getExpirationTime());
        self::assertFalse($splitToken->isEternal());
        self::assertFalse($splitToken->isExpired());
    }

    public function testRevokeToken(): void
    {
        $storage = self::getStorage();
        $startSplittoken = SplitToken::create(
            storage: $storage,
            expirationTime: time() + 3600,
            userId: self::TEST_USER_ID,
            tokenType: self::TEST_TOKEN_TYPE
        )
            ->persist();
        $token = $startSplittoken->getToken();

        /** @psalm-suppress PossiblyNullArgument */
        $splittoken = SplitToken::fromString($token, $storage);

        self::assertSame($token, $splittoken->getToken());
        self::assertFalse($splittoken->isExpired());

        $splittoken->revokeToken();
        self::assertTrue($splittoken->isExpired());
    }

    public function testRevokeEternalToken(): void
    {
        $storage = self::getStorage();
        $startSplittoken = SplitToken::create(
            storage: $storage,
            expirationTime: null,
            userId: self::TEST_USER_ID,
            tokenType: self::TEST_TOKEN_TYPE
        )
            ->persist();
        $token = $startSplittoken->getToken();

        /** @psalm-suppress PossiblyNullArgument */
        $splitToken = SplitToken::fromString($token, $storage);

        self::assertSame($token, $splitToken->getToken());
        self::assertFalse($splitToken->isExpired(), 'the token should not be expired as the time is null');
        self::assertNull($splitToken->getExpirationTime());
        self::assertTrue($splitToken->isEternal());

        $splitToken = $splitToken->revokeToken();
        self::assertTrue($splitToken->isExpired(), 'Now the token should be expired');
        self::assertNotNull($splitToken->getExpirationTime());
        self::assertFalse($splitToken->isEternal());
    }

    public function testClearExpiredTokens(): void
    {
        $storage = self::getStorage();
        $splitToken1 = SplitToken::create($storage, time() + 3600, 1)->persist();
        $splitToken2 = SplitToken::create($storage, time() + 3660, 2)->persist();
        $splitToken3 = SplitToken::create($storage, time() + 3720, 3)->persist();

        $splitToken1->revokeToken();
        $splitToken2->revokeToken();
        $splitToken3->revokeToken(true);

        self::assertSame(2, SplitToken::clearExpiredTokens($storage));
    }

    public function testTryPersistWithInvalidUserId(): void
    {
        $storage = self::getStorage();

        self::expectException(SplitTokenException::class);
        self::expectExceptionMessage('Invalid user ID');

        SplitToken::create($storage, time() + 3600, -3)->persist();
    }

    public function testInvalidTokenLength(): void
    {
        $storage = self::getStorage();

        self::expectException(InvalidTokenException::class);
        self::expectExceptionMessage('Invalid token length');

        SplitToken::fromString('abc', $storage);
    }

    public function testGetExpirationDate(): void
    {
        $storage = self::getStorage();
        $splitToken = SplitToken::create($storage, time() + 3600)->persist();

        $date = $splitToken->getExpirationDate();
        self::assertInstanceOf(DateTimeImmutable::class, $date);
    }

    public function testGetExpirationDateFormatted(): void
    {
        $storage = self::getStorage();
        $splitToken = SplitToken::create($storage, time() + 3600)->persist();

        $formatted = $splitToken->getExpirationDateFormatted();
        self::assertNotNull($formatted);
        self::assertMatchesRegularExpression('/^\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}$/', $formatted);
    }

    public function testEncryptedAdditionalInfo(): void
    {
        $storage = self::getStorage();
        $key = new SharedKey(self::TEST_KEY);

        $startToken = SplitToken::create(
            storage: $storage,
            expirationTime: time() + 3600,
            userId: self::TEST_USER_ID,
            additionalInfo: self::TEST_ADDITIONAL_INFO,
            additionalInfoKey: $key
        )
            ->persist();

        $token = $startToken->getToken();
        /** @psalm-suppress PossiblyNullArgument */
        $splitToken = SplitToken::fromString($token, $storage, $key);

        self::assertSame(self::TEST_ADDITIONAL_INFO, $splitToken->getAdditionalInfo());
    }

    public function testStringExpirationTime(): void
    {
        $storage = self::getStorage();
        $splitToken = SplitToken::create($storage, '+2 hours')->persist();

        self::assertNotNull($splitToken->getExpirationTime());
        self::assertGreaterThan(time() + 3600, $splitToken->getExpirationTime());
        self::assertFalse($splitToken->isExpired());
    }
}
