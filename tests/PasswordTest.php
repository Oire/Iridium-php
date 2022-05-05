<?php
declare(strict_types=1);
namespace Oire\Iridium\Tests;

use Oire\Iridium\Crypt;
use Oire\Iridium\Exception\PasswordException;
use Oire\Iridium\Key\SymmetricKey;
use Oire\Iridium\Password;
use PHPUnit\Framework\TestCase;

/**
 * Iridium, a security library for hashing passwords, encrypting data and managing secure tokens
 * Copyright © 2021, Andre Polykanine also known as Menelion Elensúlë, https://github.com/Oire
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
class PasswordTest extends TestCase
{
    private const CORRECT_PASSWORD = '4024Alohomora02*X%cZ/R&D';
    private const WRONG_PASSWORD = '12345Alohomora02*X%cZ/r&d';

    // Oire\Iridium\Base64::encode(hex2bin('000102030405060708090a0b0c0d0e0f'));
    private const TEST_KEY = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';

    // Oire\Iridium\Base64::encode(hex2bin('0f0e0d0c0b0a09080706050403020100'))
    private const NEW_KEY = 'Hx4dHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQA';

    public function testLockWithKnownKey(): void
    {
        $key = new SymmetricKey(self::TEST_KEY);
        $locked = Password::lock(self::CORRECT_PASSWORD, $key);

        self::assertTrue(Password::check(self::CORRECT_PASSWORD, $locked, $key));
        self::assertFalse(Password::check(self::WRONG_PASSWORD, $locked, $key));
    }

    public function testLockWithRandomKey(): void
    {
        $key = new SymmetricKey();
        $locked = Password::lock(self::CORRECT_PASSWORD, $key);

        self::assertTrue(Password::check(self::CORRECT_PASSWORD, $locked, $key));
        self::assertFalse(Password::check(self::WRONG_PASSWORD, $locked, $key));
    }

    public function testSwapKeys(): void
    {
        $oldKey = new SymmetricKey(self::TEST_KEY);
        $newKey = new SymmetricKey(self::NEW_KEY);
        $locked = Password::lock(self::CORRECT_PASSWORD, $oldKey);

        self::assertTrue(Password::check(self::CORRECT_PASSWORD, $locked, $oldKey));

        $swapped = Crypt::swapKey($locked, $oldKey, $newKey);

        self::assertTrue(Password::check(self::CORRECT_PASSWORD, $swapped, $newKey));
    }

    public function testTryDecryptWithWrongKey(): void
    {
        $key = new SymmetricKey();
        $wrongKey = new SymmetricKey();
        $locked = Password::lock(self::CORRECT_PASSWORD, $key);

        $this->expectException(PasswordException::class);
        Password::check(self::CORRECT_PASSWORD, $locked, $wrongKey);
    }
}
