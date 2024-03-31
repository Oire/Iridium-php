<?php
namespace Oire\Iridium\Key;

use Oire\Iridium\Crypt;

/**
 * Iridium, a security library for hashing passwords, encrypting data and managing secure tokens
 * Derive encryption and authentication keys for encryption.
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
final class DerivedKeys
{
    public const SALT_SIZE = 32;

    /**
     * This value objects holds the keys derived from the provided shared key.
     * Class constructor.
     * @param string $salt              The salt for deriving the keys
     * @param string $encryptionKey     the derived encryption key
     * @param string $authenticationKey The derived authentication key
     */
    public function __construct(
        private string $salt,
        private string $encryptionKey,
        private string $authenticationKey
    )
    {
    }

    /** Getters  */
    public function getSalt(): string
    {
        return $this->salt;
    }

    public function getEncryptionKey(): string
    {
        return $this->encryptionKey;
    }

    public function getAuthenticationKey(): string
    {
        return $this->authenticationKey;
    }

    /**
     * Checks if the derived keys are valid.
     * @return bool Returns true if the keys are valid, false otherwise
     */
    public function areValid(): bool
    {
        return ($this->salt && $this->encryptionKey && $this->authenticationKey)
            && mb_strlen($this->salt, Crypt::STRING_ENCODING_8BIT) === self::SALT_SIZE;
    }
}
