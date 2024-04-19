<?php

declare(strict_types=1);

namespace Oire\Iridium\Key;

use Oire\Iridium\Base64;
use Oire\Iridium\Crypt;
use Oire\Iridium\Exception\Base64Exception;
use Oire\Iridium\Exception\SharedKeyException;

/**
 * Iridium, a security library for hashing passwords, encrypting data and managing secure tokens
 * Manages shared keys for data encryption and decryption.
 * Copyright © 2021-2022, Andre Polykanine also known as Menelion Elensúlë, https://github.com/Oire
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
final class SharedKey
{
    public const KEY_SIZE = 32;
    private const ENCRYPTION_INFO = 'Iridium|V2|KeyForEncryption';
    private const AUTHENTICATION_INFO = 'Iridium|V2|KeyForAuthentication';
    private string $key;
    private string $rawKey;

    /**
     * Instantiate a new Shared Key object.
     *
     * @param string|null $key A key saved before (for example, from a .env file). If empty, a new key will be generated
     */
    public function __construct(?string $key = null)
    {
        if ($key !== null) {
            try {
                $this->rawKey = Base64::decode($key);
            } catch (Base64Exception $e) {
                throw new SharedKeyException(sprintf('Unable to decode provided key: %s.', $e->getMessage()), $e);
            }

            if (self::KEY_SIZE !== mb_strlen($this->rawKey, Crypt::STRING_ENCODING_8BIT)) {
                throw new SharedKeyException('Invalid key given.');
            }

            $this->key = $key;
        } else {
            $this->rawKey = random_bytes(self::KEY_SIZE);
            $this->key = Base64::encode($this->rawKey);
        }
    }

    /**
     * Get the key in raw binary form.
     *
     * @return string The key in binary form as a string
     */
    public function getRawKey(): string
    {
        return $this->rawKey;
    }

    /**
     * Get the key in readable and storable form.
     *
     * @return string The key in readable form as a string
     */
    public function getKey(): string
    {
        return $this->key;
    }

    /**
     * Derive encryption and authentication keys for encrypt-then-MAC.
     *
     * @param string|null $salt Salt for key derivation. Provide this only for decryption!
     *
     * @return DerivedKeys A derived keys object containing salt, encryptionKey and authenticationKey
     */
    public function deriveKeys(?string $salt = null): DerivedKeys
    {
        if ($salt !== null) {
            if (DerivedKeys::SALT_SIZE !== mb_strlen($salt, Crypt::STRING_ENCODING_8BIT)) {
                throw new SharedKeyException('Given salt is of incorrect length.');
            }
        } else {
            $salt = random_bytes(DerivedKeys::SALT_SIZE);
        }

        /** @var string|false $encryptionKey */
        $encryptionKey = hash_hkdf(Crypt::HASH_FUNCTION, $this->rawKey, 0, self::ENCRYPTION_INFO, $salt);

        if ($encryptionKey === false) {
            throw SharedKeyException::encryptionKeyFailed();
        }

        /** @var string|false $authenticationKey */
        $authenticationKey = hash_hkdf(Crypt::HASH_FUNCTION, $this->rawKey, 0, self::AUTHENTICATION_INFO, $salt);

        if ($authenticationKey === false) {
            throw SharedKeyException::authenticationKeyFailed();
        }

        return new DerivedKeys($salt, $encryptionKey, $authenticationKey);
    }

    /**
     * Get key object as string.
     *
     * @return string Returns the key in readable and storable form
     */
    public function __toString(): string
    {
        return $this->key;
    }
}
