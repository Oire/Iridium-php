<?php
declare(strict_types=1);
namespace Oire\Iridium\Tests;

use DateTimeImmutable;
use Oire\Iridium\Exception\InvalidTokenException;
use Oire\Iridium\Exception\OsstException;
use Oire\Iridium\Osst;
use Pdo;
use PHPUnit\Framework\TestCase;

/**
 * Iridium, a security library for hashing passwords, encrypting data and managing secure tokens
 * Implements the split token authentication model proposed by Paragon Initiatives.
 * Copyright © 2021 Andre Polykanine also known as Menelion Elensúlë, The Magical Kingdom of Oirë, https://github.com/Oire
 * Idea Copyright © 2017 Paragon Initiatives, https://paragonie.com/blog/2017/02/split-tokens-token-based-authentication-protocols-without-side-channels
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
class OsstTest extends TestCase
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

    /** @var PDO */
    private static $db;

    public static function setUpBeforeClass(): void
    {
        self::$db = new Pdo('sqlite::memory:');
        self::$db->query(sprintf(self::CREATE_TABLE_SQL, Osst::TABLE_NAME));
    }

    public static function tearDownAfterClass(): void
    {
        self::$db = null;
    }

    public function testSetKnownToken(): void
    {
        $expirationTime = (new DateTimeImmutable())->modify(Osst::DEFAULT_EXPIRATION_DATE_OFFSET)->getTimestamp();
        $statement = self::$db->prepare(sprintf('INSERT INTO %s (user_id, token_type, selector, verifier, additional_info, expiration_time) VALUES (:userid, :tokentype, :selector, :verifier, :additional, :expires)', Osst::TABLE_NAME));
        $statement->execute([
            ':userid' => self::TEST_USER_ID,
            ':tokentype' => self::TEST_TOKEN_TYPE,
            ':selector' => self::TEST_SELECTOR,
            ':verifier' => self::TEST_HASHED_VERIFIER,
            ':additional' => self::TEST_ADDITIONAL_INFO,
            ':expires' => $expirationTime
        ]);

        $osst = new Osst(self::$db, self::TEST_TOKEN);

        self::assertSame(self::$db, $osst->getDbConnection());
        self::assertSame(self::TEST_TOKEN, $osst->getToken());
        self::assertSame(self::TEST_USER_ID, $osst->getUserId());
        self::assertSame(self::TEST_TOKEN_TYPE, $osst->getTokenType());
        self::assertSame($expirationTime, $osst->getExpirationTime());
        self::assertSame(self::TEST_ADDITIONAL_INFO, $osst->getAdditionalInfo());
    }

    public function testCreateTokenAndSetExpirationTime(): void
    {
        $startOsst = new Osst(self::$db);
        $expirationTime = time() + 3600;
        $token = $startOsst->getToken();
        $startOsst->setUserId(self::TEST_USER_ID)->setExpirationTime($expirationTime)->setAdditionalInfo(self::TEST_ADDITIONAL_INFO)->persist();

        $osst = new Osst(self::$db, $token);

        self::assertSame($token, $osst->getToken());
        self::assertSame(self::TEST_USER_ID, $osst->getUserId());
        self::assertSame($expirationTime, $osst->getExpirationTime());
        self::assertFalse($osst->isEternal());
        self::assertNull($osst->getTokenType());
        self::assertSame(self::TEST_ADDITIONAL_INFO, $osst->getAdditionalInfo());
    }

    public function testCreateTokenAndSetExpirationOffset(): void
    {
        $startOsst = new Osst(self::$db);
        $expirationTime = (new DateTimeImmutable())->modify(Osst::DEFAULT_EXPIRATION_DATE_OFFSET)->getTimestamp();
        $token = $startOsst->getToken();
        $startOsst->setUserId(self::TEST_USER_ID)->setTokenType(self::TEST_TOKEN_TYPE)->setExpirationOffset(Osst::DEFAULT_EXPIRATION_DATE_OFFSET)->persist();

        $osst = new Osst(self::$db, $token);

        self::assertSame($token, $osst->getToken());
        self::assertSame(self::TEST_USER_ID, $osst->getUserId());
        self::assertSame(self::TEST_TOKEN_TYPE, $osst->getTokenType());
        self::assertSame($expirationTime, $osst->getExpirationTime());
        self::assertFalse($osst->isEternal());
        self::assertNull($osst->getAdditionalInfo());
    }

    public function testCreateTokenAndSetExpirationDate(): void
    {
        $startOsst = new Osst(self::$db);
        $expirationDate = (new DateTimeImmutable())->modify(Osst::DEFAULT_EXPIRATION_DATE_OFFSET);
        $token = $startOsst->getToken();
        $startOsst->setUserId(self::TEST_USER_ID)->setTokenType(self::TEST_TOKEN_TYPE)->setExpirationDate($expirationDate)->persist();

        $osst = new Osst(self::$db, $token);

        self::assertSame($token, $osst->getToken());
        self::assertSame(self::TEST_USER_ID, $osst->getUserId());
        self::assertSame(self::TEST_TOKEN_TYPE, $osst->getTokenType());
        self::assertSame($expirationDate->getTimestamp(), $osst->getExpirationDate()->getTimestamp());
        self::assertSame($expirationDate->format(Osst::DEFAULT_EXPIRATION_DATE_FORMAT), $osst->getExpirationDateFormatted());
        self::assertFalse($osst->isEternal());
        self::assertNull($osst->getAdditionalInfo());
    }

    public function testCreateEternalToken(): void
    {
        $startOsst = new Osst(self::$db);
        $token = $startOsst->getToken();
        $startOsst->setUserId(self::TEST_USER_ID)->makeEternal()->setAdditionalInfo(self::TEST_ADDITIONAL_INFO)->persist();

        $osst = new Osst(self::$db, $token);

        self::assertSame($token, $osst->getToken());
        self::assertSame(self::TEST_USER_ID, $osst->getUserId());
        self::assertSame(0, $osst->getExpirationTime());
        self::assertTrue($osst->isEternal());
        self::assertNull($osst->getTokenType());
        self::assertSame(self::TEST_ADDITIONAL_INFO, $osst->getAdditionalInfo());
    }

    public function testRevokeToken(): void
    {
        $startOsst = new Osst(self::$db);
        $expirationDate = (new DateTimeImmutable())->modify(Osst::DEFAULT_EXPIRATION_DATE_OFFSET);
        $token = $startOsst->getToken();
        $startOsst->setUserId(self::TEST_USER_ID)->setTokenType(self::TEST_TOKEN_TYPE)->setExpirationDate($expirationDate)->persist();

        $osst = new Osst(self::$db, $token);

        self::assertSame($token, $osst->getToken());
        self::assertFalse($osst->isExpired());

        $osst->revokeToken();
        self::assertTrue($osst->isExpired());
    }

    public function testRevokeEternalToken(): void
    {
        $startOsst = new Osst(self::$db);
        $token = $startOsst->getToken();
        $startOsst->setUserId(self::TEST_USER_ID)->setTokenType(self::TEST_TOKEN_TYPE)->makeEternal()->persist();

        $osst = new Osst(self::$db, $token);

        self::assertSame($token, $osst->getToken());
        self::assertFalse($osst->isExpired());
        self::assertTrue($osst->isEternal());

        $osst->revokeToken();
        self::assertTrue($osst->isExpired());
        self::assertFalse($osst->isEternal());
    }

    public function testClearExpiredTokens(): void
    {
        self::$db->query(sprintf('DELETE FROM %s', Osst::TABLE_NAME));
        $osst1 = (new Osst(self::$db))->setUserId(1)->setExpirationTime(time() + 3600)->persist();
        $osst2 = (new Osst(self::$db))->setUserId(2)->setExpirationTime(time() + 3660)->persist();
        $osst3 = (new Osst(self::$db))->setUserId(3)->setExpirationTime(time() + 3720)->persist();

        $osst1->revokeToken();
        $osst2->revokeToken();
        $osst3->revokeToken(true);

        self::assertSame(2, Osst::clearExpiredTokens(self::$db));
    }

    public function testTrySetExpirationTimeInPast(): void
    {
        self::expectException(OsstException::class);
        self::expectExceptionMessage('Expiration time cannot be in the past');

        (new Osst(self::$db))->setUserId(123)->setExpirationTime(time() - 3600)->persist();
    }

    public function testTryPersistWithInvalidUserId(): void
    {
        self::expectException(OsstException::class);
        self::expectExceptionMessage('Invalid user ID');

        (new Osst(self::$db))->persist();
    }

    public function testInvalidTokenLength(): void
    {
        self::expectException(InvalidTokenException::class);
        self::expectExceptionMessage('Invalid token length');

        new Osst(self::$db, 'abc');
    }
}
