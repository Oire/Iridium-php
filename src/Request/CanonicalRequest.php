<?php

declare(strict_types=1);

namespace Oire\Iridium\Request;

use Oire\Iridium\Exception\RequestSigningException;

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
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @psalm-pure
 */
final class CanonicalRequest
{
    public const string BODY_HASH_FUNCTION = 'sha256';

    /**
     * Build the string a request signature covers: five lines joined by a line feed, with no
     * trailing line feed.
     *
     *     context
     *     METHOD
     *     path
     *     timestamp
     *     lowercase hex SHA-256 of the raw body
     *
     * The context comes first as a domain-separation tag. The method is upper-cased. The path is
     * taken as given: both sides must agree on it byte for byte, so pass the path exactly as it
     * travels (percent-encoded, without scheme, host or query string). The timestamp is the exact
     * text that travels, never re-formatted. An empty body is hashed like any other; the line is
     * never left out.
     *
     * @throws RequestSigningException If the context is empty or a field contains a line break
     *
     * @psalm-pure
     */
    public static function build(string $context, string $method, string $path, string $timestamp, string $body): string
    {
        if ($context === '') {
            throw RequestSigningException::emptyContext();
        }

        foreach (['context' => $context, 'method' => $method, 'path' => $path, 'timestamp' => $timestamp] as $field => $value) {
            if (preg_match('/[\\r\\n]/', $value) === 1) {
                throw RequestSigningException::multilineField($field);
            }
        }

        return implode("\n", [
            $context,
            mb_strtoupper($method),
            $path,
            $timestamp,
            hash(self::BODY_HASH_FUNCTION, $body),
        ]);
    }
}
