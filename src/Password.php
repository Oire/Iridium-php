<?php

declare(strict_types=1);

namespace Oire\Iridium;

use Oire\Iridium\Exception\DecryptionException;
use Oire\Iridium\Exception\EncryptionException;
use Oire\Iridium\Exception\PasswordException;
use Oire\Iridium\Exception\SharedKeyException;
use Oire\Iridium\Key\SharedKey;

/**
 * Iridium, a security library for hashing passwords, encrypting data and managing secure tokens
 * Performs Authenticated Encryption.
 * Copyright © 2021-2022 Andre Polykanine also known as Menelion Elensúlë, https://github.com/Oire
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
final class Password
{
    /**
     * Hash password, encrypt-then-MAC the hash.
     *
     * @param string    $password The password to hash
     * @param SharedKey $key      The Iridium key for encryption
     *
     * @throws PasswordException
     * @return string            Returns encrypted result
     *
     */
    public static function lock(string $password, SharedKey $key): string
    {
        if (!$password) {
            throw new PasswordException('Password must not be empty.');
        }

        /** @var string|false|null */
        $hash = password_hash(Base64::encode(hash(Crypt::HASH_FUNCTION, $password, true)), PASSWORD_DEFAULT);

        if ($hash === false || $hash === null) {
            throw new PasswordException('Failed to hash the password.');
        }

        try {
            return Crypt::encrypt($hash, $key);
        } catch (SharedKeyException $e) {
            throw new PasswordException(sprintf('Invalid key given: %s', $e->getMessage()), $e);
        } catch (EncryptionException $e) {
            throw new PasswordException(sprintf('Encryption failed: %s.', $e->getMessage()), $e);
        }
    }

    /**
     * VerifyHMAC-then-Decrypt the ciphertext to get the hash, then verify that the hash matches the password.
     *
     * @param string    $password   The password to check
     * @param string    $cipherText The hash to match against
     * @param SharedKey $key        The Iridium key used for encryption
     *
     * @throws PasswordException
     * @return bool              Returns true if the password is valid, false otherwise
     *
     */
    public static function check(string $password, string $cipherText, SharedKey $key): bool
    {
        if (!$password) {
            throw new PasswordException('Password must not be empty.');
        }

        try {
            $hash = Crypt::decrypt($cipherText, $key);
        } catch (SharedKeyException $e) {
            throw new PasswordException(sprintf('Invalid key given: %s', $e->getMessage()), $e);
        } catch (DecryptionException $e) {
            throw new PasswordException(sprintf('Decryption failed: %s.', $e->getMessage()), $e);
        }

        return password_verify(Base64::encode(hash(Crypt::HASH_FUNCTION, $password, true)), $hash);
    }
}
