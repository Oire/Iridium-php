<?php

declare(strict_types=1);

namespace Oire\Iridium\Exception;

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
final class RequestSigningException extends IridiumException
{
    /**
     * @psalm-pure
     * @psalm-suppress PossiblyUnusedReturnValue
     */
    public static function emptyContext(): self
    {
        return new self('A request signing context cannot be empty.');
    }

    /**
     * @psalm-pure
     * @psalm-suppress PossiblyUnusedReturnValue
     */
    public static function multilineField(string $field): self
    {
        return new self(sprintf('The %s cannot contain a line break: the signed string is line-separated.', $field));
    }

    /**
     * @psalm-pure
     * @psalm-suppress PossiblyUnusedReturnValue
     */
    public static function emptyKeyId(): self
    {
        return new self('A key ID cannot be empty.');
    }

    /**
     * @psalm-pure
     * @psalm-suppress PossiblyUnusedReturnValue
     */
    public static function invalidTimestamp(int $timestamp): self
    {
        return new self(sprintf('The timestamp %d cannot be signed: it must be between 0 and 9999999999.', $timestamp));
    }

    /**
     * @psalm-pure
     * @psalm-suppress PossiblyUnusedReturnValue
     */
    public static function invalidAcceptanceWindow(int $seconds): self
    {
        return new self(sprintf('The acceptance window must be a positive number of seconds, %d given.', $seconds));
    }
}
