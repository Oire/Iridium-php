<?php

declare(strict_types=1);

namespace Oire\Iridium;

use Oire\Iridium\Exception\DecryptionException;
use Oire\Iridium\Exception\EncryptionException;
use Oire\Iridium\Exception\PasswordException;
use Oire\Iridium\Exception\SharedKeyException;
use Oire\Iridium\Key\SharedKey;
use SensitiveParameter;

/**
 * Iridium, a security library for hashing passwords, encrypting data and managing secure tokens
 * Performs password hashing and verification.
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
     */
    public static function lock(#[SensitiveParameter] string $password, SharedKey $key): string
    {
        if ($password === '') {
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
            throw new PasswordException(sprintf('Encryption failed: %s', $e->getMessage()), $e);
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
    public static function check(#[SensitiveParameter] string $password, string $cipherText, SharedKey $key): bool
    {
        if ($password === '') {
            throw new PasswordException('Password must not be empty.');
        }

        try {
            $hash = Crypt::decrypt($cipherText, $key);
        } catch (SharedKeyException $e) {
            throw new PasswordException(sprintf('Invalid key given: %s', $e->getMessage()), $e);
        } catch (DecryptionException $e) {
            throw new PasswordException(sprintf('Decryption failed: %s', $e->getMessage()), $e);
        }

        return password_verify(Base64::encode(hash(Crypt::HASH_FUNCTION, $password, true)), $hash);
    }

    /**
     * Check if a stored password hash needs rehashing (e.g., because the algorithm defaults changed).
     *
     * @param string    $cipherText The encrypted hash stored in the database
     * @param SharedKey $key        The Iridium key used for encryption
     *
     * @throws PasswordException
     * @return bool              Returns true if the hash needs rehashing, false otherwise
     */
    public static function needsRehash(string $cipherText, SharedKey $key): bool
    {
        try {
            $hash = Crypt::decrypt($cipherText, $key);
        } catch (SharedKeyException $e) {
            throw new PasswordException(sprintf('Invalid key given: %s', $e->getMessage()), $e);
        } catch (DecryptionException $e) {
            throw new PasswordException(sprintf('Decryption failed: %s', $e->getMessage()), $e);
        }

        return password_needs_rehash($hash, PASSWORD_DEFAULT);
    }
}
