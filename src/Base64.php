<?php
namespace Oire\Iridium;

use Oire\Iridium\Exception\Base64Exception;

/**
 * Iridium, a security library for hashing passwords, encrypting data and managing secure tokens
 * Copyright © 2021-2022 Andre Polykanine also known as Menelion Elensúlë, https://github.com/Oire
 *  Portions copyright © 2016 Paragon Initiative Enterprises.
 *  Portions copyright © 2014 Steve "Sc00bz" Thomas (steve at tobtu dot com)
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
final class Base64
{
    private const WHAT = '+/'; // Characters to be replaced
    private const WITH = '-_'; // Characters to replace with
    private const EXT_WHAT = '+/='; // With equals signs
    private const EXT_WITH = '-_~';

    /**
     * Encode into URL-safe Base64.
     * @param  string          $data            The data to be encoded
     * @param  bool            $preservePadding If true, replaces ='s with ~'s. If false (default), truncates padding
     * @throws Base64Exception if encoding to base64 fails
     * @return string          The encoded data
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
     * @param  string          $data The data to be decoded
     * @throws Base64Exception if decoding from Base64 fails
     * @return string          Returns decoded data
     */
    public static function decode(string $data): string
    {
        $decoded = base64_decode(strtr($data, self::WITH, self::WHAT), true);

        if ($decoded === false) {
            throw new Base64Exception('Unable to decode from base64.');
        }

        return $decoded;
    }
}
