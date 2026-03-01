<?php

declare(strict_types=1);

namespace Oire\Iridium\Tests;

use Oire\Iridium\Base64;
use Oire\Iridium\Exception\Base64Exception;
use PHPUnit\Framework\TestCase;

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
 */
final class Base64Test extends TestCase
{
    private const string RAW_DATA = 'The quick brown fox jumps over the lazy dog';
    private const string ENCODED_DATA = 'VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==';
    private const string URL_SAFE_ENCODED_DATA = 'VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw~~';
    private const string PADDINGLESS_ENCODED_DATA = 'VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw';

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

    public function testDecodeWithTildePaddedInput(): void
    {
        $encoded = Base64::encode(self::RAW_DATA, true);
        self::assertStringContainsString('~', $encoded);

        $decoded = Base64::decode($encoded);
        self::assertSame(self::RAW_DATA, $decoded);
    }
}
