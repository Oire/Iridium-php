<?php
namespace Oire\Iridium\Tests;

use Oire\Iridium\Crypt;
use Oire\Iridium\Exception\SymmetricKeyException;
use Oire\Iridium\Key\DerivedKeys;
use Oire\Iridium\Key\SymmetricKey;
use PHPUnit\Framework\TestCase;

/**
 * Iridium, a security library for hashing passwords, encrypting data and managing secure tokens
 * Manages symmetric keys for data encryption and decryption.
 * Copyright © 2021, Andre Polykanine also known as Menelion Elensúlë, The Magical Kingdom of Oirë, https://github.com/Oire
 * Copyright © 2016 Scott Arciszewski, Paragon Initiative Enterprises, https://paragonie.com.
 * Portions copyright © 2016 Taylor Hornby, Defuse Security Research and Development, https://defuse.ca.
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
class SymmetricKeyTest extends TestCase
{
    // Oire\Iridium\Base64::encode(hex2bin('000102030405060708090a0b0c0d0e0f'));
    private const TEST_KEY = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';

    public function testSetKnownKey(): void
    {
        $symmetricKey = new SymmetricKey(self::TEST_KEY);

        self::assertSame(self::TEST_KEY, $symmetricKey->getKey());
        self::assertSame(SymmetricKey::KEY_SIZE, mb_strlen($symmetricKey->getRawKey(), Crypt::STRING_ENCODING_8BIT));
    }

    public function testDeriveKeys(): void
    {
        $symmetricKey = new SymmetricKey();
        $derivedKeys = $symmetricKey->deriveKeys();

        self::assertInstanceOf(DerivedKeys::class, $derivedKeys);

        $key = $symmetricKey->getKey();
        $salt = $derivedKeys->getSalt();

        self::assertTrue($derivedKeys->areValid());
        self::assertSame(DerivedKeys::SALT_SIZE, mb_strlen($salt, Crypt::STRING_ENCODING_8BIT));

        $derivedKeys = (new SymmetricKey($key))->deriveKeys($salt);

        self::assertTrue($derivedKeys->areValid());
        self::assertSame($salt, $derivedKeys->getSalt());
    }

    public function testTrySetInvalidKey(): void
    {
        $this->expectException(SymmetricKeyException::class);

        new SymmetricKey('abc');
    }
}
