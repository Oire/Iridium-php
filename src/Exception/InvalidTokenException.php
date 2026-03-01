<?php

declare(strict_types=1);

namespace Oire\Iridium\Exception;

use Throwable;

/**
 * Iridium, a security library for hashing passwords, encrypting data and managing secure tokens
 * Copyright © 2021-2026 André Polykanine, Oire Software, https://oire.org/
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
final class InvalidTokenException extends SplitTokenException
{
    /**
     * @psalm-mutation-free
     * @psalm-suppress PossiblyUnusedReturnValue
     */
    public static function sqlError(Throwable $e): self
    {
        return new self(sprintf('SQL error: %s.', $e->getMessage()), $e);
    }

    /**
     * @psalm-pure
     * @psalm-suppress PossiblyUnusedReturnValue
     */
    public static function pdoStatementError(string $message): self
    {
        return new self(sprintf('PDO statement failed: %s.', $message));
    }

    /**
     * @psalm-pure
     * @psalm-suppress PossiblyUnusedReturnValue
     */
    public static function invalidTokenFormat(string $message, Throwable $e): self
    {
        return new self(sprintf('The token format is invalid: %s.', $message), $e);
    }

    /**
     * @psalm-pure
     * @psalm-suppress PossiblyUnusedReturnValue
     */
    public static function invalidTokenLength(): self
    {
        return new self('Invalid token length.');
    }

    /**
     * @psalm-pure
     * @psalm-suppress PossiblyUnusedReturnValue
     */
    public static function selectorError(): self
    {
        return new self('Selector is empty or does not match.');
    }

    /**
     * @psalm-pure
     * @psalm-suppress PossiblyUnusedReturnValue
     */
    public static function verifierError(): self
    {
        return new self('Verifier is empty or does not match.');
    }
}
