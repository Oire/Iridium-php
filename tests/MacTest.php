<?php

declare(strict_types=1);

namespace Oire\Iridium\Tests;

use Oire\Iridium\Base64;
use Oire\Iridium\Crypt;
use Oire\Iridium\Exception\MacException;
use Oire\Iridium\Key\SharedKey;
use Oire\Iridium\Mac;
use PHPUnit\Framework\TestCase;

/**
 * Iridium, a security library for hashing passwords, encrypting data and managing secure tokens
 * Copyright © 2021-2026 André Polykanine, Oire Software, https://oire.org/
 * Copyright © 2016 Scott Arciszewski, Paragon Initiative Enterprises, https://paragonie.com.
 * Portions copyright © 2016 Taylor Hornby, Defuse Security Research and Development, https://defuse.ca.
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
final class MacTest extends TestCase
{
    private const string CONTEXT = 'mac-test-v1';

    public function testMatchesTheGoldenVectors(): void
    {
        $vectors = RequestSigningVectors::load();
        $key = new SharedKey($vectors['key']['sharedKey']);
        $context = $vectors['context'];

        self::assertSame($vectors['macKeyHex'], bin2hex(Mac::deriveKey($key, $context)));

        foreach ($vectors['macs'] as $vector) {
            self::assertSame($vector['mac'], Mac::sign($vector['message'], $key, $context), $vector['name']);
            self::assertTrue(Mac::verify($vector['message'], $vector['mac'], $key, $context));
        }
    }

    public function testSignAndVerify(): void
    {
        $key = new SharedKey();
        $mac = Mac::sign('message', $key, self::CONTEXT);

        self::assertSame(Mac::MAC_SIZE, mb_strlen(Base64::decode($mac), Crypt::STRING_ENCODING_8BIT));
        self::assertTrue(Mac::verify('message', $mac, $key, self::CONTEXT));
        self::assertSame(Base64::decode($mac), Mac::signRaw('message', $key, self::CONTEXT));
        self::assertTrue(Mac::verifyRaw('message', Base64::decode($mac), $key, self::CONTEXT));
    }

    public function testSigningIsDeterministic(): void
    {
        $key = new SharedKey();

        self::assertSame(Mac::sign('message', $key, self::CONTEXT), Mac::sign('message', $key, self::CONTEXT));
    }

    public function testRejectsAnotherMessage(): void
    {
        $key = new SharedKey();

        self::assertFalse(Mac::verify('message!', Mac::sign('message', $key, self::CONTEXT), $key, self::CONTEXT));
    }

    public function testRejectsAnotherKey(): void
    {
        $mac = Mac::sign('message', new SharedKey(), self::CONTEXT);

        self::assertFalse(Mac::verify('message', $mac, new SharedKey(), self::CONTEXT));
    }

    public function testAContextCannotForgeForAnother(): void
    {
        $key = new SharedKey();
        $mac = Mac::sign('message', $key, 'first-context');

        self::assertNotSame($mac, Mac::sign('message', $key, 'second-context'));
        self::assertFalse(Mac::verify('message', $mac, $key, 'second-context'));
    }

    public function testTheMacKeyIsNeitherTheSharedKeyNorACryptKey(): void
    {
        $key = new SharedKey();
        $macKey = Mac::deriveKey($key, self::CONTEXT);

        self::assertSame(Mac::MAC_SIZE, mb_strlen($macKey, Crypt::STRING_ENCODING_8BIT));
        self::assertNotSame($key->getRawKey(), $macKey);
        self::assertNotSame(hash_hmac(Mac::HASH_FUNCTION, 'message', $key->getRawKey(), true), Mac::signRaw('message', $key, self::CONTEXT));
    }

    public function testTheSharedKeySurvivesSigning(): void
    {
        $key = new SharedKey();
        $rawKey = $key->getRawKey();

        Mac::sign('message', $key, self::CONTEXT);

        self::assertSame($rawKey, $key->getRawKey());
        self::assertSame(SharedKey::KEY_SIZE, mb_strlen($key->getRawKey(), Crypt::STRING_ENCODING_8BIT));
    }

    public function testAMalformedMacIsNotValid(): void
    {
        $key = new SharedKey();

        self::assertFalse(Mac::verify('message', '!!! not base64 !!!', $key, self::CONTEXT));
        self::assertFalse(Mac::verify('message', '', $key, self::CONTEXT));
        self::assertFalse(Mac::verify('message', Base64::encode(str_repeat('a', Mac::MAC_SIZE - 1)), $key, self::CONTEXT));
        self::assertFalse(Mac::verify('message', Base64::encode(str_repeat('a', Mac::MAC_SIZE + 1)), $key, self::CONTEXT));
        self::assertFalse(Mac::verifyRaw('message', '', $key, self::CONTEXT));
    }

    public function testSigningNeedsAContext(): void
    {
        $this->expectException(MacException::class);

        Mac::sign('message', new SharedKey(), '');
    }

    public function testVerifyingNeedsAContextEvenForAMalformedMac(): void
    {
        $this->expectException(MacException::class);

        Mac::verify('message', '!!! not base64 !!!', new SharedKey(), '');
    }
}
