<?php

declare(strict_types=1);

namespace Oire\Iridium\Exception;

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
class SplitTokenException extends IridiumException
{
    /** @psalm-suppress PossiblyUnusedReturnValue */
    public static function invalidUserId(int $userId = 0): self
    {
        return new self(sprintf('Invalid user ID. Should be a positive integer, %d given.', $userId));
    }

    /** @psalm-suppress PossiblyUnusedReturnValue */
    public static function additionalInfoEncryptionError(CryptException $e): self
    {
        return new self(sprintf('Unable to encrypt additional info: %s.', $e->getMessage()), $e);
    }

    /** @psalm-suppress PossiblyUnusedReturnValue */
    public static function additionalInfoDecryptionError(CryptException $e): self
    {
        return new self(sprintf('Unable to decrypt additional info: %s.', $e->getMessage()), $e);
    }
}
