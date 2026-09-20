<?php

declare(strict_types=1);

namespace Oire\Iridium\Key;

use Oire\Iridium\Exception\KeyRingException;
use Oire\Iridium\Exception\SharedKeyException;
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
final class KeyRing
{
    /** @var list<array{string, SharedKey}> */
    private array $keys = [];

    /**
     * Build a ring from stored pairs of key ID and key, typically read from configuration:
     * the current pair first, then the outgoing one kept during a rotation.
     *
     * A pair whose ID or key is null or empty is a slot that does not exist, and is skipped.
     * It is never put on the ring as an empty key: a MAC under an empty key can be forged by
     * anyone, so an unused rotation slot must not be comparable at all.
     *
     * @param iterable<array{?string, ?string}> $pairs Each pair is [key ID, key in readable form]
     *
     * @throws KeyRingException   If a key ID is repeated
     * @throws SharedKeyException If a key that is present is not a valid shared key
     */
    public static function fromPairs(#[SensitiveParameter] iterable $pairs): self
    {
        $keyRing = new self();

        foreach ($pairs as [$keyId, $key]) {
            if ($keyId === null || $keyId === '' || $key === null || $key === '') {
                continue;
            }

            $keyRing->add($keyId, new SharedKey($key));
        }

        return $keyRing;
    }

    /**
     * Put a key on the ring.
     *
     * @throws KeyRingException If the ID is empty or already on the ring
     *
     * @psalm-external-mutation-free
     */
    public function add(string $keyId, SharedKey $key): self
    {
        if ($keyId === '') {
            throw KeyRingException::emptyKeyId();
        }

        if ($this->find($keyId) !== null) {
            throw KeyRingException::duplicateKeyId($keyId);
        }

        $this->keys[] = [$keyId, $key];

        return $this;
    }

    /**
     * Find the key an ID selects. A key ID is not a secret, but it is compared in constant time anyway.
     *
     * @psalm-mutation-free
     */
    public function find(string $keyId): ?SharedKey
    {
        foreach ($this->keys as [$candidateId, $key]) {
            if (hash_equals($candidateId, $keyId)) {
                return $key;
            }
        }

        return null;
    }

    /** @psalm-mutation-free */
    public function isEmpty(): bool
    {
        return $this->keys === [];
    }

    /**
     * @psalm-mutation-free
     * @return list<string>
     */
    public function getKeyIds(): array
    {
        return array_map(static fn(array $entry): string => $entry[0], $this->keys);
    }
}
