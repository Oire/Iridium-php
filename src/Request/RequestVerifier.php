<?php

declare(strict_types=1);

namespace Oire\Iridium\Request;

use Oire\Iridium\Base64;
use Oire\Iridium\Crypt;
use Oire\Iridium\Exception\Base64Exception;
use Oire\Iridium\Exception\RequestSigningException;
use Oire\Iridium\Key\KeyRing;
use Oire\Iridium\Mac;
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
final class RequestVerifier
{
    public const int DEFAULT_ACCEPTANCE_WINDOW = 300;

    /**
     * @param KeyRing $keyRing          The keys a request may be signed with, selected by key ID
     * @param string  $context          The same context the signing side uses
     * @param int     $acceptanceWindow How far, in seconds, a timestamp may be from this clock, either way.
     *                                  It is also how long a captured request can be replayed, so keep it short
     *
     * @throws RequestSigningException If the context is empty or the window is not positive
     *
     * @psalm-pure
     */
    public function __construct(
        private readonly KeyRing $keyRing,
        private readonly string $context,
        private readonly int $acceptanceWindow = self::DEFAULT_ACCEPTANCE_WINDOW,
    ) {
        if ($context === '') {
            throw RequestSigningException::emptyContext();
        }

        if ($acceptanceWindow <= 0) {
            throw RequestSigningException::invalidAcceptanceWindow($acceptanceWindow);
        }
    }

    /**
     * Verify a signed request. Returns null when it is accepted, the reason otherwise.
     *
     * The signature is checked before the timestamp's age, so StaleTimestamp always means a
     * correctly signed request from a clock that is off, and nothing else.
     *
     * There is no nonce: an identical request is accepted again for as long as its timestamp
     * stays inside the window.
     *
     * @param string      $method    The HTTP method as received
     * @param string      $path      The path as received: percent-encoded, no base path, no query string
     * @param string      $body      The raw body as received
     * @param string|null $keyId     The received key ID, null if absent
     * @param string|null $timestamp The received timestamp, null if absent
     * @param string|null $signature The received signature, null if absent
     * @param int|null    $now       Unix seconds to judge the timestamp against; the current time if null
     */
    public function verify(
        string $method,
        string $path,
        string $body,
        ?string $keyId,
        ?string $timestamp,
        #[SensitiveParameter]
        ?string $signature,
        ?int $now = null,
    ): ?RequestVerificationFailure {
        if ($keyId === null || $timestamp === null || $signature === null) {
            return RequestVerificationFailure::MissingFields;
        }

        // The timestamp is signed as text, so "0123" and "123" must not both be acceptable.
        if (preg_match('/\\A(?:0|[1-9]\\d{0,9})\\z/', $timestamp) !== 1) {
            return RequestVerificationFailure::MalformedField;
        }

        try {
            $rawSignature = Base64::decode($signature);
        } catch (Base64Exception) {
            return RequestVerificationFailure::MalformedField;
        }

        if (Mac::MAC_SIZE !== mb_strlen($rawSignature, Crypt::STRING_ENCODING_8BIT)) {
            return RequestVerificationFailure::MalformedField;
        }

        $key = $this->keyRing->find($keyId);

        if ($key === null) {
            return RequestVerificationFailure::UnknownKeyId;
        }

        try {
            $canonical = CanonicalRequest::build($this->context, $method, $path, $timestamp, $body);
        } catch (RequestSigningException) {
            return RequestVerificationFailure::MalformedField;
        }

        if (!Mac::verifyRaw($canonical, $rawSignature, $key, $this->context)) {
            return RequestVerificationFailure::BadSignature;
        }

        if (abs(($now ?? time()) - (int) $timestamp) > $this->acceptanceWindow) {
            return RequestVerificationFailure::StaleTimestamp;
        }

        return null;
    }
}
