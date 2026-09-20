<?php

declare(strict_types=1);

namespace Oire\Iridium\Tests;

use Oire\Iridium\Exception\KeyRingException;
use Oire\Iridium\Exception\SharedKeyException;
use Oire\Iridium\Key\KeyRing;
use Oire\Iridium\Key\SharedKey;
use PHPUnit\Framework\TestCase;

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
final class KeyRingTest extends TestCase
{
    public function testFindsAKeyByItsId(): void
    {
        $current = new SharedKey();
        $previous = new SharedKey();
        $keyRing = (new KeyRing())->add('current', $current)->add('previous', $previous);

        self::assertSame($current, $keyRing->find('current'));
        self::assertSame($previous, $keyRing->find('previous'));
        self::assertNull($keyRing->find('unknown'));
        self::assertSame(['current', 'previous'], $keyRing->getKeyIds());
        self::assertFalse($keyRing->isEmpty());
    }

    public function testBuildsFromStoredPairs(): void
    {
        $current = new SharedKey();
        $previous = new SharedKey();
        $keyRing = KeyRing::fromPairs([['current', $current->getKey()], ['previous', $previous->getKey()]]);

        self::assertSame($current->getRawKey(), $keyRing->find('current')?->getRawKey());
        self::assertSame($previous->getRawKey(), $keyRing->find('previous')?->getRawKey());
    }

    public function testASlotThatIsNotFilledDoesNotExist(): void
    {
        $key = (new SharedKey())->getKey();
        $keyRing = KeyRing::fromPairs([
            ['current', $key],
            ['', ''],
            [null, null],
            ['id-without-a-key', ''],
            ['id-with-a-null-key', null],
            ['', $key],
            [null, $key],
        ]);

        self::assertSame(['current'], $keyRing->getKeyIds());
        self::assertNull($keyRing->find(''));
        self::assertNull($keyRing->find('id-without-a-key'));
        self::assertNull($keyRing->find('id-with-a-null-key'));
    }

    public function testARingWithNoFilledSlotIsEmpty(): void
    {
        self::assertTrue(KeyRing::fromPairs([['', ''], [null, null]])->isEmpty());
        self::assertTrue((new KeyRing())->isEmpty());
    }

    public function testAKeyThatIsPresentMustBeValid(): void
    {
        $this->expectException(SharedKeyException::class);

        KeyRing::fromPairs([['current', 'too-short']]);
    }

    public function testAnEmptyIdCannotBeAdded(): void
    {
        $this->expectException(KeyRingException::class);

        (new KeyRing())->add('', new SharedKey());
    }

    public function testAnIdCannotBeAddedTwice(): void
    {
        $this->expectException(KeyRingException::class);

        (new KeyRing())->add('current', new SharedKey())->add('current', new SharedKey());
    }

    public function testARepeatedStoredIdIsRefused(): void
    {
        $this->expectException(KeyRingException::class);

        KeyRing::fromPairs([['same', (new SharedKey())->getKey()], ['same', (new SharedKey())->getKey()]]);
    }
}
