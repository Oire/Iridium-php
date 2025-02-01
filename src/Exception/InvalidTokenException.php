<?php

declare(strict_types=1);

namespace Oire\Iridium\Exception;

use Throwable;

/**
 * Iridium, a security library for hashing passwords, encrypting data and managing secure tokens
 * Copyright © 2021-2025 André Polykanine also known as Menelion Elensúlë, Oire Software, https://github.com/Oire
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
final class InvalidTokenException extends SplitTokenException
{
    /** @psalm-suppress PossiblyUnusedReturnValue */
    public static function sqlError(Throwable $e): self
    {
        return new self(sprintf('SQL error: %s.', $e->getMessage()), $e);
    }

    /** @psalm-suppress PossiblyUnusedReturnValue */
    public static function pdoStatementError(string $message): self
    {
        return new self(sprintf('PDO statement failed: %s.', $message));
    }

    /** @psalm-suppress PossiblyUnusedReturnValue */
    public static function invalidTokenFormat(string $message, Throwable $e): self
    {
        return new self(sprintf('The token format is invalid: %s.', $message), $e);
    }

    /** @psalm-suppress PossiblyUnusedReturnValue */
    public static function invalidTokenLength(): self
    {
        return new self('Invalid token length.');
    }

    /** @psalm-suppress PossiblyUnusedReturnValue */
    public static function selectorError(): self
    {
        return new self('Selector is empty or does not match.');
    }

    /** @psalm-suppress PossiblyUnusedReturnValue */
    public static function verifierError(): self
    {
        return new self('Verifier is empty or does not match.');
    }
}
