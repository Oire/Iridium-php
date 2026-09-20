<?php

declare(strict_types=1);

namespace Oire\Iridium\Request;

use Oire\Iridium\Exception\MacException;
use Oire\Iridium\Exception\RequestSigningException;
use Oire\Iridium\Key\SharedKey;
use Oire\Iridium\Mac;

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
final class RequestSigner
{
    private const int MAXIMUM_TIMESTAMP = 9_999_999_999;

    /**
     * @param string    $keyId   The ID the verifying side knows this key by
     * @param SharedKey $key     The shared key
     * @param string    $context What these signatures are for, such as "myapp-api-v1". It is both
     *                           the first signed line and the label the MAC key is derived under
     *
     * @throws RequestSigningException If the key ID or the context is empty
     *
     * @psalm-pure
     */
    public function __construct(
        private readonly string $keyId,
        private readonly SharedKey $key,
        private readonly string $context,
    ) {
        if ($keyId === '') {
            throw RequestSigningException::emptyKeyId();
        }

        if ($context === '') {
            throw RequestSigningException::emptyContext();
        }
    }

    /**
     * Sign a request.
     *
     * @param string   $method    The HTTP method
     * @param string   $path      The path exactly as it travels: percent-encoded, no query string
     * @param string   $body      The raw body, empty for a request without one
     * @param int|null $timestamp Unix seconds; now if null. Pass your own to correct for a known clock offset
     *
     * @throws RequestSigningException
     * @throws MacException
     */
    public function sign(string $method, string $path, string $body = '', ?int $timestamp = null): SignedRequest
    {
        $timestamp ??= time();

        if ($timestamp < 0 || $timestamp > self::MAXIMUM_TIMESTAMP) {
            throw RequestSigningException::invalidTimestamp($timestamp);
        }

        $timestampText = (string) $timestamp;
        $canonical = CanonicalRequest::build($this->context, $method, $path, $timestampText, $body);

        return new SignedRequest($this->keyId, $timestampText, Mac::sign($canonical, $this->key, $this->context));
    }
}
