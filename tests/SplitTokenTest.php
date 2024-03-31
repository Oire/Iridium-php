<?php
declare(strict_types=1);
namespace Oire\Iridium\Tests;

use DateTimeImmutable;
use Oire\Iridium\Exception\InvalidTokenException;
use Oire\Iridium\Exception\SplitTokenException;
use Oire\Iridium\SplitToken;
use PDO;
use PHPUnit\Framework\TestCase;

/**
 * Iridium, a security library for hashing passwords, encrypting data and managing secure tokens
 * Copyright © 2021-2022 Andre Polykanine also known as Menelion Elensúlë, https://github.com/Oire
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 */
class SplitTokenTest extends TestCase
{
    // Oire\Iridium\Base64::encode(hex2bin('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324'));
    private const TEST_TOKEN = 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMk';
    private const TEST_SELECTOR = 'AQIDBAUGBwgJCgsMDQ4PEA';
    private const TEST_VERIFIER = 'ERITFBUWFxgZGhscHR4fICEiIyQ';
    private const TEST_HASHED_VERIFIER = 'UTYMVAte1GIu5QtgTAgjJ_Nb0R8ys_O-WdDbTMZPUbncmjA-hOJGZNM1aNedoBEH';
    private const TEST_USER_ID = 12345;
    private const TEST_TOKEN_TYPE = 3;
    private const TEST_ADDITIONAL_INFO = '{"oldEmail":"test@example.com","newEmail":"john.doe@example.com"}';
    private const CREATE_TABLE_SQL = <<<'SQL'
            CREATE TABLE %s (
                id INTEGER NOT NULL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                token_type INTEGER,
                selector TEXT NOT NULL UNIQUE,
                verifier TEXT NOT NULL UNIQUE,
                additional_info TEXT,
                expiration_time BIGINT NOT NULL
            );
        SQL;
    private static PDO $db;

    public static function setUpBeforeClass(): void
    {
        self::$db = new PDO('sqlite::memory:');
        self::$db->query(sprintf(self::CREATE_TABLE_SQL, SplitToken::TABLE_NAME));
    }

    public static function tearDownAfterClass(): void
    {
        self::$db = null;
    }

    public function testSetKnownToken(): void
    {
        $expirationTime = (new DateTimeImmutable())->modify(SplitToken::DEFAULT_EXPIRATION_DATE_OFFSET)->getTimestamp();
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
            ':expires' => $expirationTime
        ]);

        $splittoken = new Splittoken(self::$db, self::TEST_TOKEN);

        self::assertSame(self::$db, $splittoken->getDbConnection());
        self::assertSame(self::TEST_TOKEN, $splittoken->getToken());
        self::assertSame(self::TEST_USER_ID, $splittoken->getUserId());
        self::assertSame(self::TEST_TOKEN_TYPE, $splittoken->getTokenType());
        self::assertSame($expirationTime, $splittoken->getExpirationTime());
        self::assertSame(self::TEST_ADDITIONAL_INFO, $splittoken->getAdditionalInfo());
    }

    public function testCreateTokenAndSetExpirationTime(): void
    {
        $startSplittoken = new Splittoken(self::$db);
        $expirationTime = time() + 3600;
        $token = $startSplittoken->getToken();
        $startSplittoken
            ->setUserId(self::TEST_USER_ID)
            ->setExpirationTime($expirationTime)
            ->setAdditionalInfo(self::TEST_ADDITIONAL_INFO)
            ->persist();

        $splittoken = new Splittoken(self::$db, $token);

        self::assertSame($token, $splittoken->getToken());
        self::assertSame(self::TEST_USER_ID, $splittoken->getUserId());
        self::assertSame($expirationTime, $splittoken->getExpirationTime());
        self::assertFalse($splittoken->isEternal());
        self::assertNull($splittoken->getTokenType());
        self::assertSame(self::TEST_ADDITIONAL_INFO, $splittoken->getAdditionalInfo());
    }

    public function testCreateTokenAndSetExpirationOffset(): void
    {
        $startSplittoken = new Splittoken(self::$db);
        $expirationTime = (new DateTimeImmutable())->modify(Splittoken::DEFAULT_EXPIRATION_DATE_OFFSET)->getTimestamp();
        $token = $startSplittoken->getToken();
        $startSplittoken
            ->setUserId(self::TEST_USER_ID)
            ->setTokenType(self::TEST_TOKEN_TYPE)
            ->setExpirationOffset(Splittoken::DEFAULT_EXPIRATION_DATE_OFFSET)
            ->persist();

        $splittoken = new Splittoken(self::$db, $token);

        self::assertSame($token, $splittoken->getToken());
        self::assertSame(self::TEST_USER_ID, $splittoken->getUserId());
        self::assertSame(self::TEST_TOKEN_TYPE, $splittoken->getTokenType());
        self::assertSame($expirationTime, $splittoken->getExpirationTime());
        self::assertFalse($splittoken->isEternal());
        self::assertNull($splittoken->getAdditionalInfo());
    }

    public function testCreateTokenAndSetExpirationDate(): void
    {
        $startSplittoken = new Splittoken(self::$db);
        $expirationDate = (new DateTimeImmutable())->modify(Splittoken::DEFAULT_EXPIRATION_DATE_OFFSET);
        $token = $startSplittoken->getToken();
        $startSplittoken
            ->setUserId(self::TEST_USER_ID)
            ->setTokenType(self::TEST_TOKEN_TYPE)
            ->setExpirationDate($expirationDate)
            ->persist();

        $splittoken = new Splittoken(self::$db, $token);

        self::assertSame($token, $splittoken->getToken());
        self::assertSame(self::TEST_USER_ID, $splittoken->getUserId());
        self::assertSame(self::TEST_TOKEN_TYPE, $splittoken->getTokenType());
        self::assertSame($expirationDate->getTimestamp(), $splittoken->getExpirationDate()->getTimestamp());
        self::assertSame(
            $expirationDate->format(Splittoken::DEFAULT_EXPIRATION_DATE_FORMAT),
            $splittoken->getExpirationDateFormatted()
        );
        self::assertFalse($splittoken->isEternal());
        self::assertNull($splittoken->getAdditionalInfo());
    }

    public function testCreateEternalToken(): void
    {
        $startSplittoken = new Splittoken(self::$db);
        $token = $startSplittoken->getToken();
        $startSplittoken
            ->setUserId(self::TEST_USER_ID)
            // ->makeEternal()
            ->setAdditionalInfo(self::TEST_ADDITIONAL_INFO)
            ->persist();

        $splittoken = new Splittoken(self::$db, $token);

        self::assertSame($token, $splittoken->getToken());
        self::assertSame(self::TEST_USER_ID, $splittoken->getUserId());
        self::assertSame(0, $splittoken->getExpirationTime());
        self::assertTrue($splittoken->isEternal());
        self::assertNull($splittoken->getTokenType());
        self::assertSame(self::TEST_ADDITIONAL_INFO, $splittoken->getAdditionalInfo());
    }

    public function testRevokeToken(): void
    {
        $startSplittoken = new Splittoken(self::$db);
        $expirationDate = (new DateTimeImmutable())->modify(Splittoken::DEFAULT_EXPIRATION_DATE_OFFSET);
        $token = $startSplittoken->getToken();
        $startSplittoken
            ->setUserId(self::TEST_USER_ID)
            ->setTokenType(self::TEST_TOKEN_TYPE)
            ->setExpirationDate($expirationDate)
            ->persist();

        $splittoken = new Splittoken(self::$db, $token);

        self::assertSame($token, $splittoken->getToken());
        self::assertFalse($splittoken->isExpired());

        $splittoken->revokeToken();
        self::assertTrue($splittoken->isExpired());
    }

    public function testRevokeEternalToken(): void
    {
        $startSplittoken = new Splittoken(self::$db);
        $token = $startSplittoken->getToken();
        $startSplittoken->setUserId(self::TEST_USER_ID)->setTokenType(self::TEST_TOKEN_TYPE)->makeEternal()->persist();

        $splittoken = new Splittoken(self::$db, $token);

        self::assertSame($token, $splittoken->getToken());
        self::assertFalse($splittoken->isExpired());
        self::assertTrue($splittoken->isEternal());

        $splittoken->revokeToken();
        self::assertTrue($splittoken->isExpired());
        self::assertFalse($splittoken->isEternal());
    }

    public function testClearExpiredTokens(): void
    {
        self::$db->query(sprintf('DELETE FROM %s', Splittoken::TABLE_NAME));
        $splittoken1 = (new Splittoken(self::$db))->setUserId(1)->setExpirationTime(time() + 3600)->persist();
        $splittoken2 = (new Splittoken(self::$db))->setUserId(2)->setExpirationTime(time() + 3660)->persist();
        $splittoken3 = (new Splittoken(self::$db))->setUserId(3)->setExpirationTime(time() + 3720)->persist();

        $splittoken1->revokeToken();
        $splittoken2->revokeToken();
        $splittoken3->revokeToken(true);

        self::assertSame(2, Splittoken::clearExpiredTokens(self::$db));
    }

    public function testTrySetExpirationTimeInPast(): void
    {
        self::expectException(SplittokenException::class);
        self::expectExceptionMessage('Expiration time cannot be in the past');

        (new Splittoken(self::$db))->setUserId(123)->setExpirationTime(time() - 3600)->persist();
    }

    public function testTryPersistWithInvalidUserId(): void
    {
        self::expectException(SplittokenException::class);
        self::expectExceptionMessage('Invalid user ID');

        (new Splittoken(self::$db))->persist();
    }

    public function testInvalidTokenLength(): void
    {
        self::expectException(InvalidTokenException::class);
        self::expectExceptionMessage('Invalid token length');

        new Splittoken(self::$db, 'abc');
    }
}
