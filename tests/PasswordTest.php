<?php

declare(strict_types=1);

namespace Oire\Iridium\Tests;

use Oire\Iridium\Crypt;
use Oire\Iridium\Exception\PasswordException;
use Oire\Iridium\Key\SharedKey;
use Oire\Iridium\Password;
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
final class PasswordTest extends TestCase
{
    private const string CORRECT_PASSWORD = '4024Alohomora02*X%cZ/R&D';
    private const string WRONG_PASSWORD = '12345Alohomora02*X%cZ/r&d';

    // Oire\Iridium\Base64::encode(hex2bin('000102030405060708090a0b0c0d0e0f'));
    private const string TEST_KEY = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';

    // Oire\Iridium\Base64::encode(hex2bin('0f0e0d0c0b0a09080706050403020100'))
    private const string NEW_KEY = 'Hx4dHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQA';

    public function testLockWithKnownKey(): void
    {
        $key = new SharedKey(self::TEST_KEY);
        $locked = Password::lock(self::CORRECT_PASSWORD, $key);

        self::assertTrue(Password::check(self::CORRECT_PASSWORD, $locked, $key));
        self::assertFalse(Password::check(self::WRONG_PASSWORD, $locked, $key));
    }

    public function testLockWithRandomKey(): void
    {
        $key = new SharedKey();
        $locked = Password::lock(self::CORRECT_PASSWORD, $key);

        self::assertTrue(Password::check(self::CORRECT_PASSWORD, $locked, $key));
        self::assertFalse(Password::check(self::WRONG_PASSWORD, $locked, $key));
    }

    public function testSwapKeys(): void
    {
        $oldKey = new SharedKey(self::TEST_KEY);
        $newKey = new SharedKey(self::NEW_KEY);
        $locked = Password::lock(self::CORRECT_PASSWORD, $oldKey);

        self::assertTrue(Password::check(self::CORRECT_PASSWORD, $locked, $oldKey));

        $swapped = Crypt::swapKey($locked, $oldKey, $newKey);

        self::assertTrue(Password::check(self::CORRECT_PASSWORD, $swapped, $newKey));
    }

    public function testTryDecryptWithWrongKey(): void
    {
        $key = new SharedKey();
        $wrongKey = new SharedKey();
        $locked = Password::lock(self::CORRECT_PASSWORD, $key);

        $this->expectException(PasswordException::class);
        Password::check(self::CORRECT_PASSWORD, $locked, $wrongKey);
    }
}
