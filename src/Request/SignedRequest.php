<?php

declare(strict_types=1);

namespace Oire\Iridium\Request;

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
 * The three values a signed request carries beside its method, path and body. Iridium does not
 * name the headers: send them under whatever names your API uses.
 *
 * @psalm-immutable
 */
final readonly class SignedRequest
{
    /**
     * @param string $keyId     Which key signed the request. Not a secret
     * @param string $timestamp Unix seconds, exactly as signed. Send these bytes unchanged
     * @param string $signature The MAC as URL-safe Base64 without padding
     *
     * @psalm-mutation-free
     */
    public function __construct(
        public string $keyId,
        public string $timestamp,
        public string $signature,
    ) {}
}
