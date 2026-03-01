<?php

declare(strict_types=1);

namespace Oire\Iridium\Tests;

use DateTimeImmutable;
use Oire\Iridium\Exception\InvalidTokenException;
use Oire\Iridium\Exception\SplitTokenException;
use Oire\Iridium\SplitToken;
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
    private static ?PDO $db;

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

        $schema = file_get_contents(__DIR__ . '/schema.sql');
        self::$db->exec(sprintf('DROP TABLE IF EXISTS %s', SplitToken::TABLE_NAME));
        /** @psalm-suppress PossiblyFalseArgument */
        self::$db->exec($schema);
    }

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
        self::$db = null;
    }

    public function testSetTokenFromsUserProvidedString(): void
    {
        $expirationTime = (new DateTimeImmutable(SplitToken::DEFAULT_EXPIRATION_TIME_OFFSET))->getTimestamp();

        /** @psalm-suppress PossiblyNullReference */
        $statement = self::$db->prepare(
            sprintf(
                'INSERT INTO %s (
                    user_id, token_type, selector, verifier, additional_info, expiration_time
                ) VALUES (
                    :userid, :tokentype, :selector, :verifier, :additional, :expires
                )',
                SplitToken::TABLE_NAME
            )
        );
        $statement->execute([
            ':userid' => self::TEST_USER_ID,
            ':tokentype' => self::TEST_TOKEN_TYPE,
            ':selector' => self::TEST_SELECTOR,
            ':verifier' => self::TEST_HASHED_VERIFIER,
            ':additional' => self::TEST_ADDITIONAL_INFO,
            ':expires' => $expirationTime,
        ]);

        /** @psalm-suppress PossiblyNullArgument */
        $splittoken = SplitToken::fromString(self::TEST_TOKEN, self::$db);

        self::assertSame(self::TEST_TOKEN, $splittoken->getToken());
        self::assertSame(self::TEST_USER_ID, $splittoken->getUserId());
        self::assertSame(self::TEST_TOKEN_TYPE, $splittoken->getTokenType());
        self::assertSame($expirationTime, $splittoken->getExpirationTime());
        self::assertSame(self::TEST_ADDITIONAL_INFO, $splittoken->getAdditionalInfo());
    }

    public function testCreateToken(): void
    {
        $expirationTime = time() + 10800;
        /** @psalm-suppress PossiblyNullArgument */
        $startSplitToken = SplitToken::create(
            dbConnection: self::$db,
            expirationTime: $expirationTime,
            userId: self::TEST_USER_ID,
            tokenType: null,
            additionalInfo: self::TEST_ADDITIONAL_INFO
        )
            ->persist();
        $token = $startSplitToken->getToken();

        /** @psalm-suppress PossiblyNullArgument */
        $splittoken = SplitToken::fromString($token, self::$db);

        self::assertSame($token, $splittoken->getToken());
        self::assertSame(self::TEST_USER_ID, $splittoken->getUserId());
        self::assertSame($expirationTime, $splittoken->getExpirationTime());
        self::assertFalse($splittoken->isEternal());
        self::assertNull($splittoken->getTokenType());
        self::assertSame(self::TEST_ADDITIONAL_INFO, $splittoken->getAdditionalInfo());
    }

    public function testCreateEternalToken(): void
    {
        /** @psalm-suppress PossiblyNullArgument */
        $startSplittoken = SplitToken::create(self::$db, null)->persist();
        $token = $startSplittoken->getToken();
        $splittoken = SplitToken::fromString($token, self::$db);

        self::assertSame($token, $splittoken->getToken());
        self::assertNull($splittoken->getUserId());
        self::assertNull($splittoken->getExpirationTime());
        self::assertTrue($splittoken->isEternal());
        self::assertNull($splittoken->getTokenType());
        self::assertNull($splittoken->getAdditionalInfo());
    }

    public function testSetDefaultExpirationTime(): void
    {
        /** @psalm-suppress PossiblyNullArgument */
        $startSplitToken = SplitToken::create(self::$db)->persist();
        $token = $startSplitToken->getToken();
        /** @psalm-suppress PossiblyNullArgument */
        $splitToken = SplitToken::fromString($token, self::$db);

        self::assertSame($token, $splitToken->getToken());
        self::assertNotNull($splitToken->getExpirationTime());
        self::assertGreaterThan(time(), $splitToken->getExpirationTime());
        self::assertFalse($splitToken->isEternal());
        self::assertFalse($splitToken->isExpired());
    }

    public function testRevokeToken(): void
    {
        /** @psalm-suppress PossiblyNullArgument */
        $startSplittoken = SplitToken::create(
            dbConnection: self::$db,
            expirationTime: time() + 3600,
            userId: self::TEST_USER_ID,
            tokenType: self::TEST_TOKEN_TYPE
        )
            ->persist();
        $token = $startSplittoken->getToken();

        $splittoken = SplitToken::fromString($token, self::$db);

        self::assertSame($token, $splittoken->getToken());
        self::assertFalse($splittoken->isExpired());

        $splittoken->revokeToken();
        self::assertTrue($splittoken->isExpired());
    }

    public function testRevokeEternalToken(): void
    {
        /** @psalm-suppress PossiblyNullArgument */
        $startSplittoken = SplitToken::create(
            dbConnection: self::$db,
            expirationTime: null,
            userId: self::TEST_USER_ID,
            tokenType: self::TEST_TOKEN_TYPE
        )
            ->persist();
        $token = $startSplittoken->getToken();

        /** @psalm-suppress PossiblyNullArgument */
        $splitToken = SplitToken::fromString($token, self::$db);

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
        /** @psalm-suppress PossiblyNullArgument */
        $splitToken1 = SplitToken::create(self::$db, time() + 3600, 1)->persist();
        /** @psalm-suppress PossiblyNullArgument */
        $splitToken2 = SplitToken::create(self::$db, time() + 3660, 2)->persist();
        /** @psalm-suppress PossiblyNullArgument */
        $splitToken3 = SplitToken::create(self::$db, time() + 3720, 3)->persist();

        $splitToken1->revokeToken();
        $splitToken2->revokeToken();
        $splitToken3->revokeToken(true);

        self::assertSame(2, SplitToken::clearExpiredTokens(self::$db));
    }

    public function testTryPersistWithInvalidUserId(): void
    {
        self::expectException(SplitTokenException::class);
        self::expectExceptionMessage('Invalid user ID');

        /** @psalm-suppress PossiblyNullArgument */
        SplitToken::create(self::$db, time() + 3600, -3)->persist();
    }

    public function testInvalidTokenLength(): void
    {
        self::expectException(InvalidTokenException::class);
        self::expectExceptionMessage('Invalid token length');

        /** @psalm-suppress PossiblyNullArgument */
        SplitToken::fromString('abc', self::$db);
    }
}
