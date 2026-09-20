<?php

declare(strict_types=1);

namespace Oire\Iridium\Tests;

use RuntimeException;

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
/**
 * @psalm-type MacVector = array{name: string, message: string, mac: string}
 * @psalm-type RequestVector = array{name: string, method: string, path: string, timestamp: string, body: string, bodySha256Hex: string, canonical: string, signature: string}
 * @psalm-type Vectors = array{key: array{keyId: string, sharedKey: string, sharedKeyHex: string}, context: string, derivationInfo: string, macKeyHex: string, macs: non-empty-list<MacVector>, requests: non-empty-list<RequestVector>}
 */
final class RequestSigningVectors
{
    /**
     * The shape is pinned by the tests that read it.
     *
     * @psalm-suppress MixedReturnStatement
     * @return Vectors
     */
    public static function load(): array
    {
        $json = file_get_contents(__DIR__ . '/fixtures/request-signing-vectors.json');

        if ($json === false) {
            throw new RuntimeException('The request signing vectors are missing.');
        }

        return json_decode($json, true, 32, JSON_THROW_ON_ERROR);
    }
}
