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
 * Copyright © 2021-2025 André Polykanine also known as Menelion Elensúlë, Oire Software, https://github.com/Oire
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
final class Crypt
{
    public const HASH_FUNCTION = 'sha384';
    public const HASH_SIZE = 48;
    public const ENCRYPTION_ALGORITHM = 'aes-256-ctr';
    public const STRING_ENCODING_8BIT = '8bit';
    private const IV_SIZE = 16;
    private const MINIMUM_CIPHER_TEXT_SIZE = 96;

    /**
     * Encrypt data with a given key.
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

        if (!$plainText) {
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

        $iv = random_bytes(self::IV_SIZE);
        $encrypted = openssl_encrypt(
            $plainText,
            self::ENCRYPTION_ALGORITHM,
            $derivedKeys->getEncryptionKey(),
            OPENSSL_RAW_DATA,
            $iv
        );

        if ($encrypted === false) {
            throw new EncryptionException('OpenSSL encryption failed.');
        }

        $cipherText = $derivedKeys->getSalt() . $iv . $encrypted;

        /** @var string|false */
        $hmac = hash_hmac(self::HASH_FUNCTION, $cipherText, $derivedKeys->getAuthenticationKey(), true);

        if ($hmac === false) {
            throw EncryptionException::hmacFailed();
        }

        $cipherText = $cipherText . $hmac;

        return Base64::encode($cipherText);
    }

    /**
     * Decrypt data with a given key.
     *
     * @param string    $cipherText The encrypted data, as a string
     * @param SharedKey $key        The Iridium key the data was encrypted with
     *
     * @throws DecryptionException
     * @return string              the decrypted plain text
     *
     */
    public static function decrypt(string $cipherText, SharedKey $key): string
    {
        if (!function_exists('openssl_decrypt')) {
            throw new DecryptionException('OpenSSL decryption not available.');
        }

        if (!$cipherText) {
            throw new DecryptionException('Cipher text must not be empty.');
        }

        try {
            $cipherText = Base64::decode($cipherText);
        } catch (Base64Exception $e) {
            throw new DecryptionException(sprintf('Failed to decode cipher text: %s.', $e->getMessage()), $e);
        }

        if (mb_strlen($cipherText, self::STRING_ENCODING_8BIT) < self::MINIMUM_CIPHER_TEXT_SIZE) {
            throw new DecryptionException('Given cipher text is of incorrect length.');
        }

        /** @var string|false */
        $salt = mb_substr($cipherText, 0, DerivedKeys::SALT_SIZE, self::STRING_ENCODING_8BIT);

        if ($salt === false) {
            throw new DecryptionException('Invalid salt given.');
        }

        try {
            $derivedKeys = $key->deriveKeys($salt);
        } catch (SharedKeyException $e) {
            throw new DecryptionException(sprintf('Unable to derive keys: %s.', $e->getMessage()), $e);
        }

        if (!$derivedKeys->areValid()) {
            throw new EncryptionException('Derived keys are invalid');
        }

        /** @var string|false */
        $iv = mb_substr($cipherText, DerivedKeys::SALT_SIZE, self::IV_SIZE, self::STRING_ENCODING_8BIT);

        if ($iv === false) {
            throw new DecryptionException('Invalid initialization vector given.');
        }

        /** @var string|false */
        $hmac = mb_substr($cipherText, -self::HASH_SIZE, null, self::STRING_ENCODING_8BIT);

        if ($hmac === false) {
            throw DecryptionException::hmacFailed();
        }

        /** @var string|false */
        $encrypted = mb_substr(
            $cipherText,
            DerivedKeys::SALT_SIZE + self::IV_SIZE,
            mb_strlen($cipherText, self::STRING_ENCODING_8BIT)
                - self::HASH_SIZE
                - DerivedKeys::SALT_SIZE
                - self::IV_SIZE,
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
            $encrypted,
            self::ENCRYPTION_ALGORITHM,
            $derivedKeys->getEncryptionKey(),
            OPENSSL_RAW_DATA,
            $iv
        );

        if ($plainText === false) {
            throw new DecryptionException('OpenSSL decryption failed.');
        }

        return $plainText;
    }

    /**
     * Change encryption key (for instance, if the old one is compromised).
     *
     * @param string    $cipherText The encrypted data
     * @param SharedKey $oldKey     The key the data was encrypted before
     * @param SharedKey $newKey     The key for re-encrypting the data
     *
     * @throws SharedKeyException
     * @return string             Returns the re-encrypted data
     *
     */
    public static function swapKey(string $cipherText, SharedKey $oldKey, SharedKey $newKey): string
    {
        try {
            $plainText = self::decrypt($cipherText, $oldKey);
        } catch (SharedKeyException $e) {
            throw new CryptException(sprintf('Invalid old key: %s', $e->getMessage()), $e);
        } catch (DecryptionException $e) {
            throw new CryptException(sprintf('Decryption failed: %s.', $e->getMessage()), $e);
        }

        try {
            return self::encrypt($plainText, $newKey);
        } catch (SharedKeyException $e) {
            throw new CryptException(sprintf('Invalid new key: %s', $e->getMessage()), $e);
        } catch (EncryptionException $e) {
            throw new CryptException(sprintf('Encryption failed: %s.', $e->getMessage()), $e);
        }
    }
}
