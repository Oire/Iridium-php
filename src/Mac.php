<?php

declare(strict_types=1);

namespace Oire\Iridium;

use Oire\Iridium\Exception\Base64Exception;
use Oire\Iridium\Exception\MacException;
use Oire\Iridium\Key\SharedKey;
use SensitiveParameter;

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
final class Mac
{
    public const string HASH_FUNCTION = 'sha256';
    public const int MAC_SIZE = 32;
    private const string DERIVATION_INFO_PREFIX = 'Iridium|Mac|V1|';

    /**
     * Authenticate a message with HMAC-SHA256.
     *
     * The shared key is never used directly. The MAC key is derived from it with HKDF-SHA256
     * (empty salt, 32 bytes, info = "Iridium|Mac|V1|" followed by the context), so the same
     * shared key can safely serve Crypt and any number of MAC contexts without one use being
     * able to forge for another.
     *
     * @param string    $message The message to authenticate
     * @param SharedKey $key     The shared key
     * @param string    $context What this MAC is for, such as "myapp-api-v1". Cannot be empty
     *
     * @throws MacException
     * @return string       The MAC as URL-safe Base64 without padding
     */
    public static function sign(string $message, SharedKey $key, string $context): string
    {
        return Base64::encode(self::signRaw($message, $key, $context));
    }

    /**
     * Authenticate a message and get the MAC as 32 raw bytes.
     *
     * @throws MacException
     */
    public static function signRaw(string $message, SharedKey $key, string $context): string
    {
        $macKey = self::deriveKey($key, $context);
        $mac = hash_hmac(self::HASH_FUNCTION, $message, $macKey, true);
        sodium_memzero($macKey);

        return $mac;
    }

    /**
     * Check a MAC in constant time. A MAC that is malformed or of the wrong length is simply not valid.
     *
     * @param string $mac The MAC as URL-safe Base64, as returned by sign()
     *
     * @throws MacException If the context is empty
     */
    public static function verify(string $message, #[SensitiveParameter] string $mac, SharedKey $key, string $context): bool
    {
        try {
            $rawMac = Base64::decode($mac);
        } catch (Base64Exception) {
            // The context is still validated, so a misuse is not hidden behind a bad MAC.
            self::deriveKey($key, $context);

            return false;
        }

        return self::verifyRaw($message, $rawMac, $key, $context);
    }

    /**
     * Check a raw 32-byte MAC in constant time.
     *
     * @throws MacException If the context is empty
     */
    public static function verifyRaw(string $message, #[SensitiveParameter] string $rawMac, SharedKey $key, string $context): bool
    {
        $expected = self::signRaw($message, $key, $context);

        if (self::MAC_SIZE !== mb_strlen($rawMac, Crypt::STRING_ENCODING_8BIT)) {
            return false;
        }

        return hash_equals($expected, $rawMac);
    }

    /**
     * Derive the 32-byte MAC key of a context. Exposed so that a client in another language can
     * be checked against it; you do not need it to sign or verify.
     *
     * @throws MacException
     *
     * @psalm-mutation-free
     */
    public static function deriveKey(SharedKey $key, string $context): string
    {
        if ($context === '') {
            throw MacException::emptyContext();
        }

        return hash_hkdf(self::HASH_FUNCTION, $key->getRawKey(), self::MAC_SIZE, self::DERIVATION_INFO_PREFIX . $context);
    }
}
