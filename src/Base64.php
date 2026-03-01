<?php

declare(strict_types=1);

namespace Oire\Iridium;

use Oire\Iridium\Exception\Base64Exception;

/**
 * Iridium, a security library for hashing passwords, encrypting data and managing secure tokens
 * Copyright © 2021-2026 André Polykanine, Oire Software, https://oire.org/
 * Portions copyright © 2016 Paragon Initiative Enterprises.
 * Portions copyright © 2014 Steve "Sc00bz" Thomas (steve at tobtu dot com).
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
 * @psalm-pure
 */
final class Base64
{
    private const string WHAT = '+/'; // Characters to be replaced
    private const string WITH = '-_'; // Characters to replace with
    private const string EXT_WHAT = '+/='; // With equals signs
    private const string EXT_WITH = '-_~';

    /**
     * Encode into URL-safe Base64.
     *
     * @param string $data            The data to be encoded
     * @param bool   $preservePadding If true, replaces ='s with ~'s. If false (default), truncates padding
     *
     * @return string The encoded data
     *
     * @psalm-pure
     */
    public static function encode(string $data, bool $preservePadding = false): string
    {
        $b64 = base64_encode($data);

        return $preservePadding
            ? strtr($b64, self::EXT_WHAT, self::EXT_WITH)
            : strtr(rtrim($b64, '='), self::WHAT, self::WITH);
    }

    /**
     * Decode from URL-safe Base64.
     *
     * @param string $data The data to be decoded
     *
     * @throws Base64Exception if decoding from Base64 fails
     * @return string          Returns decoded data
     *
     * @psalm-pure
     */
    public static function decode(string $data): string
    {
        $decoded = base64_decode(strtr($data, self::EXT_WITH, self::EXT_WHAT), true);

        if ($decoded === false) {
            throw new Base64Exception('Unable to decode from base64.');
        }

        return $decoded;
    }
}
