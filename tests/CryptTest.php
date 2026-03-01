<?php

declare(strict_types=1);

namespace Oire\Iridium\Tests;

use Oire\Iridium\Base64;
use Oire\Iridium\Crypt;
use Oire\Iridium\Exception\DecryptionException;
use Oire\Iridium\Exception\EncryptionException;
use Oire\Iridium\Key\SharedKey;
use Override;
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
final class CryptTest extends TestCase
{
    // Oire\Iridium\Base64::encode(hex2bin('000102030405060708090a0b0c0d0e0f'));
    private const string TEST_KEY = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';

    // Oire\Iridium\Base64::encode(hex2bin('0f0e0d0c0b0a09080706050403020100'))
    private const string NEW_KEY = 'Hx4dHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQA';
    private const string DECRYPTABLE_DATA = 'Mischief managed!';

    /**
     * Pre-computed v1 (AES-256-CTR + HMAC-SHA384) test vector.
     * Encrypted "Mischief managed!" with TEST_KEY using legacy v1 format.
     */
    private static string $legacyV1Vector = '';

    /** @psalm-suppress MissingPureAnnotation */
    #[Override]
    public static function setUpBeforeClass(): void
    {
        // Generate a v1 test vector by directly using the legacy format
        $key = new SharedKey(self::TEST_KEY);
        $derivedKeys = $key->deriveKeys();
        $iv = random_bytes(16);
        $encrypted = openssl_encrypt(
            self::DECRYPTABLE_DATA,
            'aes-256-ctr',
            $derivedKeys->getEncryptionKey(),
            OPENSSL_RAW_DATA,
            $iv
        );

        if ($encrypted === false) {
            self::fail('OpenSSL encryption failed during v1 test vector generation.');
        }

        $cipherText = $derivedKeys->getSalt() . $iv . $encrypted;
        $hmac = hash_hmac('sha384', $cipherText, $derivedKeys->getAuthenticationKey(), true);
        self::$legacyV1Vector = Base64::encode($cipherText . $hmac);
    }

    public function testEncryptAndDecryptWithKnownKey(): void
    {
        $key = new SharedKey(self::TEST_KEY);
        $encrypted = Crypt::encrypt(self::DECRYPTABLE_DATA, $key);

        self::assertSame(self::DECRYPTABLE_DATA, Crypt::decrypt($encrypted, $key));
    }

    public function testEncryptAndDecryptWithRandomKey(): void
    {
        $key = new SharedKey();
        $encrypted = Crypt::encrypt(self::DECRYPTABLE_DATA, $key);

        self::assertSame(self::DECRYPTABLE_DATA, Crypt::decrypt($encrypted, $key));
    }

    public function testTryDecryptingCorruptData(): void
    {
        $key = new SharedKey();

        $this->expectException(DecryptionException::class);

        Crypt::decrypt('abc', $key);
    }

    public function testSwapKnownKeys(): void
    {
        $oldKey = new SharedKey(self::TEST_KEY);
        $newKey = new SharedKey(self::NEW_KEY);
        $encrypted = Crypt::encrypt(self::DECRYPTABLE_DATA, $oldKey);

        self::assertSame(self::DECRYPTABLE_DATA, Crypt::decrypt($encrypted, $oldKey));

        $swapped = Crypt::swapKey($encrypted, $oldKey, $newKey);

        self::assertSame(self::DECRYPTABLE_DATA, Crypt::decrypt($swapped, $newKey));
    }

    public function testSwapRandomKeys(): void
    {
        $oldKey = new SharedKey();
        $newKey = new SharedKey();
        $encrypted = Crypt::encrypt(self::DECRYPTABLE_DATA, $oldKey);

        self::assertSame(self::DECRYPTABLE_DATA, Crypt::decrypt($encrypted, $oldKey));

        $swapped = Crypt::swapKey($encrypted, $oldKey, $newKey);

        self::assertSame(self::DECRYPTABLE_DATA, Crypt::decrypt($swapped, $newKey));
    }

    public function testEncryptEmptyStringThrows(): void
    {
        $key = new SharedKey();

        $this->expectException(EncryptionException::class);

        Crypt::encrypt('', $key);
    }

    public function testDecryptEmptyStringThrows(): void
    {
        $key = new SharedKey();

        $this->expectException(DecryptionException::class);

        Crypt::decrypt('', $key);
    }

    public function testDecryptWithWrongKeyThrows(): void
    {
        $key = new SharedKey();
        $wrongKey = new SharedKey();
        $encrypted = Crypt::encrypt(self::DECRYPTABLE_DATA, $key);

        $this->expectException(DecryptionException::class);

        Crypt::decrypt($encrypted, $wrongKey);
    }

    public function testGcmEncryptionAndDecryption(): void
    {
        $key = new SharedKey(self::TEST_KEY);
        $encrypted = Crypt::encrypt(self::DECRYPTABLE_DATA, $key);

        // Verify the encrypted data starts with version byte 0x02
        $raw = Base64::decode($encrypted);
        self::assertSame(2, ord($raw[0]));

        // Verify round-trip
        self::assertSame(self::DECRYPTABLE_DATA, Crypt::decrypt($encrypted, $key));
    }

    public function testLegacyV1Decryption(): void
    {
        $key = new SharedKey(self::TEST_KEY);

        self::assertSame(self::DECRYPTABLE_DATA, Crypt::decrypt(self::$legacyV1Vector, $key));
    }

    public function testSwapKeyMigratesV1ToV2(): void
    {
        $key = new SharedKey(self::TEST_KEY);
        $newKey = new SharedKey(self::NEW_KEY);

        // Verify v1 vector can be decrypted
        self::assertSame(self::DECRYPTABLE_DATA, Crypt::decrypt(self::$legacyV1Vector, $key));

        // Swap key — this re-encrypts with v2
        $swapped = Crypt::swapKey(self::$legacyV1Vector, $key, $newKey);

        // Verify new ciphertext uses v2 format (version byte 0x02)
        $raw = Base64::decode($swapped);
        self::assertSame(2, ord($raw[0]));

        // Verify the content is still correct
        self::assertSame(self::DECRYPTABLE_DATA, Crypt::decrypt($swapped, $newKey));
    }
}
