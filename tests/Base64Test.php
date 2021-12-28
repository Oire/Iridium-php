<?php
declare(strict_types=1);
namespace Oire\Iridium\Tests;

use Oire\Iridium\Base64;
use Oire\Iridium\Exception\Base64Exception;
use PHPUnit\Framework\TestCase;

/**
 * Iridium, a security library for hashing passwords, encrypting data and managing secure tokens
 * Copyright © 2021, Andre Polykanine also known as Menelion Elensúlë, https://github.com/Oire
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
class Base64Test extends TestCase
{
    private const RAW_DATA = 'The quick brown fox jumps over the lazy dog';
    private const ENCODED_DATA = 'VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==';
    private const URL_SAFE_ENCODED_DATA = 'VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw~~';
    private const PADDINGLESS_ENCODED_DATA = 'VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw';

    public function testDataEquality(): void
    {
        self::assertSame(Base64::decode(Base64::encode(self::RAW_DATA)), self::RAW_DATA);
    }

    public function testEncodingValidity(): void
    {
        self::assertSame(Base64::encode(self::RAW_DATA), self::PADDINGLESS_ENCODED_DATA);
    }

    public function testUrlSafeness(): void
    {
        self::assertNotSame(Base64::encode(self::RAW_DATA, true), self::ENCODED_DATA);
        self::assertSame(Base64::encode(self::RAW_DATA, true), self::URL_SAFE_ENCODED_DATA);
    }

    public function testPadding(): void
    {
        self::assertNotSame(Base64::encode(self::RAW_DATA), self::URL_SAFE_ENCODED_DATA);
        self::assertSame(Base64::encode(self::RAW_DATA, true), self::URL_SAFE_ENCODED_DATA);
    }

    public function testNonBase64Alphabet(): void
    {
        self::expectException(Base64Exception::class);
        self::expectExceptionMessage('Unable to decode from base64.');

        Base64::decode(random_bytes(32));
    }
}
