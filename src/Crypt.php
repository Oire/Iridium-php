<?php

declare(strict_types=1);

namespace Oire\Iridium;

use Oire\Iridium\Exception\Base64Exception;
use Oire\Iridium\Exception\CryptException;
use Oire\Iridium\Exception\DecryptionException;
use Oire\Iridium\Exception\EncryptionException;
use Oire\Iridium\Exception\SharedKeyException;
use Oire\Iridium\Key\DerivedKeys;
use Oire\Iridium\Key\SharedKey;

/**
 * Iridium, a security library for hashing passwords, encrypting data and managing secure tokens
 * Performs Authenticated Encryption.
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
final class Crypt
{
    public const string HASH_FUNCTION = 'sha384';
    public const int HASH_SIZE = 48;
    public const string ENCRYPTION_ALGORITHM = 'aes-256-gcm';
    public const string STRING_ENCODING_8BIT = '8bit';
    private const int VERSION_1 = 1;
    private const int VERSION_2 = 2;
    private const string LEGACY_ENCRYPTION_ALGORITHM = 'aes-256-ctr';
    private const int LEGACY_IV_SIZE = 16;
    private const int LEGACY_MINIMUM_CIPHER_TEXT_SIZE = 96;
    private const int GCM_NONCE_SIZE = 12;
    private const int GCM_TAG_SIZE = 16;

    /**
     * Encrypt data with a given key using AES-256-GCM.
     *
     * @param string    $plainText The data to be encrypted
     * @param SharedKey $key       The Iridium key used for encryption
     *
     * @throws EncryptionException
     * @return string              Returns the encrypted data
     */
    public static function encrypt(string $plainText, SharedKey $key): string
    {
        if (!function_exists('openssl_encrypt')) {
            throw new EncryptionException('OpenSSL encryption not available.');
        }

        if ($plainText === '') {
            throw new EncryptionException('The data to encrypt must not be empty.');
        }

        try {
            $derivedKeys = $key->deriveKeys();
        } catch (SharedKeyException $e) {
            throw new EncryptionException(sprintf('Unable to derive keys: %s', $e->getMessage()), $e);
        }

        if (!$derivedKeys->areValid()) {
            throw new EncryptionException('Derived keys are invalid.');
        }

        $nonce = random_bytes(self::GCM_NONCE_SIZE);
        $tag = '';
        $encrypted = openssl_encrypt(
            data: $plainText,
            cipher_algo: self::ENCRYPTION_ALGORITHM,
            passphrase: $derivedKeys->getEncryptionKey(),
            options: OPENSSL_RAW_DATA,
            iv: $nonce,
            tag: $tag,
            aad: '',
            tag_length: self::GCM_TAG_SIZE
        );

        if ($encrypted === false) {
            throw new EncryptionException('OpenSSL encryption failed.');
        }

        $cipherText = chr(self::VERSION_2) . $derivedKeys->getSalt() . $nonce . $encrypted . $tag;

        return Base64::encode($cipherText);
    }

    /**
     * Decrypt data with a given key. Supports both v2 (AES-256-GCM) and legacy v1 (AES-256-CTR + HMAC-SHA384).
     *
     * @param string    $cipherText The encrypted data, as a string
     * @param SharedKey $key        The Iridium key the data was encrypted with
     *
     * @throws DecryptionException
     * @return string              the decrypted plain text
     */
    public static function decrypt(string $cipherText, SharedKey $key): string
    {
        if (!function_exists('openssl_decrypt')) {
            throw new DecryptionException('OpenSSL decryption not available.');
        }

        if ($cipherText === '') {
            throw new DecryptionException('Cipher text must not be empty.');
        }

        try {
            $raw = Base64::decode($cipherText);
        } catch (Base64Exception $e) {
            throw new DecryptionException(sprintf('Failed to decode cipher text: %s.', $e->getMessage()), $e);
        }

        if ($raw === '') {
            throw new DecryptionException('Given cipher text is of incorrect length.');
        }

        $versionByte = ord($raw[0]);

        if ($versionByte === self::VERSION_2) {
            try {
                return self::decryptV2($raw, $key);
            } catch (DecryptionException) {
                // Fallback: the first byte could be 0x02 by coincidence in v1 data (1/256 chance).
                return self::decryptV1($raw, $key);
            }
        }

        return self::decryptV1($raw, $key);
    }

    /**
     * Change encryption key (for instance, if the old one is compromised).
     * Decrypts with the old key (auto-detecting version) and re-encrypts with the new key using v2 (GCM).
     *
     * @param string    $cipherText The encrypted data
     * @param SharedKey $oldKey     The key the data was encrypted before
     * @param SharedKey $newKey     The key for re-encrypting the data
     *
     * @throws CryptException
     * @return string         Returns the re-encrypted data
     */
    public static function swapKey(string $cipherText, SharedKey $oldKey, SharedKey $newKey): string
    {
        try {
            $plainText = self::decrypt($cipherText, $oldKey);
        } catch (SharedKeyException $e) {
            throw new CryptException(sprintf('Invalid old key: %s', $e->getMessage()), $e);
        } catch (DecryptionException $e) {
            throw new CryptException(sprintf('Decryption failed: %s', $e->getMessage()), $e);
        }

        try {
            return self::encrypt($plainText, $newKey);
        } catch (SharedKeyException $e) {
            throw new CryptException(sprintf('Invalid new key: %s', $e->getMessage()), $e);
        } catch (EncryptionException $e) {
            throw new CryptException(sprintf('Encryption failed: %s', $e->getMessage()), $e);
        }
    }

    /**
     * Decrypt using legacy v1 format: AES-256-CTR + HMAC-SHA384.
     * Format: salt(32) + iv(16) + encrypted + hmac(48)
     */
    private static function decryptV1(string $raw, SharedKey $key): string
    {
        if (mb_strlen($raw, self::STRING_ENCODING_8BIT) < self::LEGACY_MINIMUM_CIPHER_TEXT_SIZE) {
            throw new DecryptionException('Given cipher text is of incorrect length.');
        }

        /** @var string|false */
        $salt = mb_substr($raw, 0, DerivedKeys::SALT_SIZE, self::STRING_ENCODING_8BIT);

        if ($salt === false) {
            throw new DecryptionException('Invalid salt given.');
        }

        try {
            $derivedKeys = $key->deriveKeys($salt);
        } catch (SharedKeyException $e) {
            throw new DecryptionException(sprintf('Unable to derive keys: %s.', $e->getMessage()), $e);
        }

        if (!$derivedKeys->areValid()) {
            throw new DecryptionException('Derived keys are invalid.');
        }

        /** @var string|false */
        $iv = mb_substr($raw, DerivedKeys::SALT_SIZE, self::LEGACY_IV_SIZE, self::STRING_ENCODING_8BIT);

        if ($iv === false) {
            throw new DecryptionException('Invalid initialization vector given.');
        }

        /** @var string|false */
        $hmac = mb_substr($raw, -self::HASH_SIZE, null, self::STRING_ENCODING_8BIT);

        if ($hmac === false) {
            throw DecryptionException::hmacFailed();
        }

        /** @var string|false */
        $encrypted = mb_substr(
            $raw,
            DerivedKeys::SALT_SIZE + self::LEGACY_IV_SIZE,
            mb_strlen($raw, self::STRING_ENCODING_8BIT)
                - self::HASH_SIZE
                - DerivedKeys::SALT_SIZE
                - self::LEGACY_IV_SIZE,
            self::STRING_ENCODING_8BIT
        );

        if ($encrypted === false) {
            throw new DecryptionException('Invalid encrypted text given.');
        }

        /** @var string|false $message */
        $message = hash_hmac(self::HASH_FUNCTION, $salt . $iv . $encrypted, $derivedKeys->getAuthenticationKey(), true);

        if ($message === false) {
            throw DecryptionException::hmacFailed();
        }

        if (!hash_equals($hmac, $message)) {
            throw new DecryptionException('HMAC mismatch.');
        }

        $plainText = openssl_decrypt(
            data: $encrypted,
            cipher_algo: self::LEGACY_ENCRYPTION_ALGORITHM,
            passphrase: $derivedKeys->getEncryptionKey(),
            options: OPENSSL_RAW_DATA,
            iv: $iv
        );

        if ($plainText === false) {
            throw new DecryptionException('OpenSSL decryption failed.');
        }

        return $plainText;
    }

    /**
     * Decrypt using v2 format: AES-256-GCM.
     * Format: version(1) + salt(32) + nonce(12) + encrypted + tag(16)
     */
    private static function decryptV2(string $raw, SharedKey $key): string
    {
        $rawLength = mb_strlen($raw, self::STRING_ENCODING_8BIT);
        // Minimum: 1 (version) + 32 (salt) + 12 (nonce) + 1 (min ciphertext) + 16 (tag) = 62
        $minimumLength = 1 + DerivedKeys::SALT_SIZE + self::GCM_NONCE_SIZE + 1 + self::GCM_TAG_SIZE;

        if ($rawLength < $minimumLength) {
            throw new DecryptionException('Given cipher text is of incorrect length.');
        }

        $offset = 1; // skip version byte

        /** @var string|false */
        $salt = mb_substr($raw, $offset, DerivedKeys::SALT_SIZE, self::STRING_ENCODING_8BIT);

        if ($salt === false) {
            throw new DecryptionException('Invalid salt given.');
        }

        $offset += DerivedKeys::SALT_SIZE;

        try {
            $derivedKeys = $key->deriveKeys($salt);
        } catch (SharedKeyException $e) {
            throw new DecryptionException(sprintf('Unable to derive keys: %s.', $e->getMessage()), $e);
        }

        if (!$derivedKeys->areValid()) {
            throw new DecryptionException('Derived keys are invalid.');
        }

        /** @var string|false */
        $nonce = mb_substr($raw, $offset, self::GCM_NONCE_SIZE, self::STRING_ENCODING_8BIT);

        if ($nonce === false) {
            throw new DecryptionException('Invalid nonce given.');
        }

        $offset += self::GCM_NONCE_SIZE;

        $encryptedLength = $rawLength - $offset - self::GCM_TAG_SIZE;

        /** @var string|false */
        $encrypted = mb_substr($raw, $offset, $encryptedLength, self::STRING_ENCODING_8BIT);

        if ($encrypted === false) {
            throw new DecryptionException('Invalid encrypted text given.');
        }

        /** @var string|false */
        $tag = mb_substr($raw, -self::GCM_TAG_SIZE, null, self::STRING_ENCODING_8BIT);

        if ($tag === false) {
            throw new DecryptionException('Invalid authentication tag given.');
        }

        $plainText = openssl_decrypt(
            data: $encrypted,
            cipher_algo: self::ENCRYPTION_ALGORITHM,
            passphrase: $derivedKeys->getEncryptionKey(),
            options: OPENSSL_RAW_DATA,
            iv: $nonce,
            tag: $tag
        );

        if ($plainText === false) {
            throw new DecryptionException('OpenSSL decryption failed.');
        }

        return $plainText;
    }
}
