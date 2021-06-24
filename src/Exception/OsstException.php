<?php
declare(strict_types=1);
namespace Oire\Iridium\Exception;

/**
 * Iridium, a security library for hashing passwords, encrypting data and managing secure tokens
 * Implements the split token authentication model proposed by Paragon Initiatives.
 * Copyright © 2021 Andre Polykanine also known as Menelion Elensúlë, The magical kingdom of Oirë, https://github.com/Oire
 * Idea Copyright © 2017 Paragon Initiatives, https://paragonie.com/blog/2017/02/split-tokens-token-based-authentication-protocols-without-side-channels
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
class OsstException extends IridiumException
{
    /** @psalm-suppress PossiblyUnusedReturnValue */
    final public static function invalidUserId(int $userId = 0): self
    {
        return new self(sprintf('Invalid user ID. Should be a positive integer, %d given.', $userId));
    }

    /** @psalm-suppress PossiblyUnusedReturnValue */
    final public static function emptyExpirationOffset(): self
    {
        return new self('Expiration offset must not be empty.');
    }

    /** @psalm-suppress PossiblyUnusedReturnValue */
    final public static function emptyExpirationTime(): self
    {
        return new self('Expiration time cannot be empty, set or create the token first.');
    }

    /** @psalm-suppress PossiblyUnusedReturnValue */
    final public static function expirationTimeInPast(int $expirationTime): self
    {
        return new self(sprintf('Expiration time cannot be in the past. The difference is -%d seconds.', time() - $expirationTime));
    }

    /** @psalm-suppress PossiblyUnusedReturnValue */
    final public static function tokenNotSet(): self
    {
        return new self('The token is not set, please retrieve or create it first.');
    }

    /** @psalm-suppress PossiblyUnusedReturnValue */
    final public static function propertyAlreadySet(string $property): self
    {
        return new self(sprintf('%s is already set in token validation.', ucfirst($property)));
    }

    /** @psalm-suppress PossiblyUnusedReturnValue */
    final public static function additionalInfoEncryptionError(CryptException $e): self
    {
        return new self(sprintf('Unable to encrypt additional info: %s.', $e->getMessage()), $e);
    }

    /** @psalm-suppress PossiblyUnusedReturnValue */
    final public static function additionalInfoDecryptionError(CryptException $e): self
    {
        return new self(sprintf('Unable to decrypt additional info: %s.', $e->getMessage()), $e);
    }

    /** @psalm-suppress PossiblyUnusedReturnValue */
    final public static function tokenNeverExpires(): self
    {
        return new self('The token never expires.');
    }
}
