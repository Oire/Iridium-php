<?php
declare(strict_types=1);
namespace Oire\Iridium\Tests;

use Oire\Iridium\Crypt;
use Oire\Iridium\Exception\DecryptionException;
use Oire\Iridium\Key\SymmetricKey;
use PHPUnit\Framework\TestCase;

/**
 * Iridium, a security library for hashing passwords, encrypting data and managing secure tokens
 * Performs Authenticated Encryption.
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
class CryptTest extends TestCase
{
    // Oire\Iridium\Base64::encode(hex2bin('000102030405060708090a0b0c0d0e0f'));
    private const TEST_KEY = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';
    // Oire\Iridium\Base64::encode(hex2bin('0f0e0d0c0b0a09080706050403020100'))
    private const NEW_KEY = 'Hx4dHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQA';
    private const DECRYPTABLE_DATA = 'Mischief managed!';

    public function testEncryptAndDecryptWithKnownKey(): void
    {
        $key = new SymmetricKey(self::TEST_KEY);
        $encrypted = Crypt::encrypt(self::DECRYPTABLE_DATA, $key);

        self::assertSame(self::DECRYPTABLE_DATA, Crypt::decrypt($encrypted, $key));
    }

    public function testEncryptAndDecryptWithRandomKey(): void
    {
        $key = new SymmetricKey();
        $encrypted = Crypt::encrypt(self::DECRYPTABLE_DATA, $key);

        self::assertSame(self::DECRYPTABLE_DATA, Crypt::decrypt($encrypted, $key));
    }

    public function testTryDecryptingCorruptData(): void
    {
        $key = new SymmetricKey();

        $this->expectException(DecryptionException::class);

        Crypt::decrypt('abc', $key);
    }

    public function testSwapKnownKeys(): void
    {
        $oldKey = new SymmetricKey(self::TEST_KEY);
        $newKey = new SymmetricKey(self::NEW_KEY);
        $encrypted = Crypt::encrypt(self::DECRYPTABLE_DATA, $oldKey);

        self::assertSame(self::DECRYPTABLE_DATA, Crypt::decrypt($encrypted, $oldKey));

        $swapped = Crypt::swapKey($encrypted, $oldKey, $newKey);

        self::assertSame(self::DECRYPTABLE_DATA, Crypt::decrypt($swapped, $newKey));
    }

    public function testSwapRandomKeys(): void
    {
        $oldKey = new SymmetricKey();
        $newKey = new SymmetricKey();
        $encrypted = Crypt::encrypt(self::DECRYPTABLE_DATA, $oldKey);

        self::assertSame(self::DECRYPTABLE_DATA, Crypt::decrypt($encrypted, $oldKey));

        $swapped = Crypt::swapKey($encrypted, $oldKey, $newKey);

        self::assertSame(self::DECRYPTABLE_DATA, Crypt::decrypt($swapped, $newKey));
    }
}
