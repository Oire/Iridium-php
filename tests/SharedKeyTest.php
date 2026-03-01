<?php

declare(strict_types=1);

namespace Oire\Iridium\Tests;

use Oire\Iridium\Crypt;
use Oire\Iridium\Exception\SharedKeyException;
use Oire\Iridium\Key\DerivedKeys;
use Oire\Iridium\Key\SharedKey;
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
final class SharedKeyTest extends TestCase
{
    // Oire\Iridium\Base64::encode(hex2bin('000102030405060708090a0b0c0d0e0f'));
    private const string TEST_KEY = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';

    public function testSetKnownKey(): void
    {
        $sharedKey = new SharedKey(self::TEST_KEY);

        self::assertSame(self::TEST_KEY, $sharedKey->getKey());
        self::assertSame(SharedKey::KEY_SIZE, mb_strlen($sharedKey->getRawKey(), Crypt::STRING_ENCODING_8BIT));
    }

    public function testDeriveKeys(): void
    {
        $sharedKey = new SharedKey();
        $derivedKeys = $sharedKey->deriveKeys();

        self::assertInstanceOf(DerivedKeys::class, $derivedKeys);

        $key = $sharedKey->getKey();
        $salt = $derivedKeys->getSalt();

        self::assertTrue($derivedKeys->areValid());
        self::assertSame(DerivedKeys::SALT_SIZE, mb_strlen($salt, Crypt::STRING_ENCODING_8BIT));

        $derivedKeys = (new SharedKey($key))->deriveKeys($salt);

        self::assertTrue($derivedKeys->areValid());
        self::assertSame($salt, $derivedKeys->getSalt());
    }

    public function testTrySetInvalidKey(): void
    {
        $this->expectException(SharedKeyException::class);

        new SharedKey('abc');
    }

    public function testToString(): void
    {
        $sharedKey = new SharedKey(self::TEST_KEY);

        self::assertSame($sharedKey->getKey(), (string) $sharedKey);
    }

    public function testCreateFactoryMethod(): void
    {
        $randomKey = SharedKey::create();
        self::assertSame(SharedKey::KEY_SIZE, mb_strlen($randomKey->getRawKey(), Crypt::STRING_ENCODING_8BIT));

        $knownKey = SharedKey::create(self::TEST_KEY);
        self::assertSame(self::TEST_KEY, $knownKey->getKey());
    }

    public function testDeriveKeysWithInvalidSaltLengthThrows(): void
    {
        $sharedKey = new SharedKey();

        $this->expectException(SharedKeyException::class);

        $sharedKey->deriveKeys('short');
    }

    public function testDerivedKeysAreValidReturnsFalse(): void
    {
        $derivedKeys = new DerivedKeys('', '', '');

        self::assertFalse($derivedKeys->areValid());
    }
}
