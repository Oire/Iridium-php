<?php

declare(strict_types=1);

namespace Oire\Iridium\Key;

use Oire\Iridium\Crypt;
use SensitiveParameter;

/**
 * Iridium, a security library for hashing passwords, encrypting data and managing secure tokens
 * Derive encryption and authentication keys for encryption.
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
 *
 */
final class DerivedKeys
{
    public const int SALT_SIZE = 32;

    /**
     * This value object holds the keys derived from the provided shared key.
     * Class constructor.
     *
     * @param string $salt              The salt for deriving the keys
     * @param string $encryptionKey     the derived encryption key
     * @param string $authenticationKey The derived authentication key
     *
     * @psalm-mutation-free
     */
    public function __construct(
        #[SensitiveParameter]
        private string $salt,
        #[SensitiveParameter]
        private string $encryptionKey,
        #[SensitiveParameter]
        private string $authenticationKey
    ) {}

    public function __destruct()
    {
        sodium_memzero($this->salt);
        sodium_memzero($this->encryptionKey);
        sodium_memzero($this->authenticationKey);
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
     *
     * @return bool Returns true if the keys are valid, false otherwise
     *
     * @psalm-mutation-free
     */
    public function areValid(): bool
    {
        return ($this->salt !== '' && $this->encryptionKey !== '' && $this->authenticationKey !== '')
            && self::SALT_SIZE === mb_strlen($this->salt, Crypt::STRING_ENCODING_8BIT);
    }
}
