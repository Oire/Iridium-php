<?php

declare(strict_types=1);

namespace Oire\Iridium\Tests;

use Oire\Iridium\Base64;
use Oire\Iridium\Exception\RequestSigningException;
use Oire\Iridium\Key\KeyRing;
use Oire\Iridium\Key\SharedKey;
use Oire\Iridium\Mac;
use Oire\Iridium\Request\CanonicalRequest;
use Oire\Iridium\Request\RequestSigner;
use Oire\Iridium\Request\RequestVerificationFailure;
use Oire\Iridium\Request\RequestVerifier;
use Oire\Iridium\Request\SignedRequest;
use Override;
use PHPUnit\Framework\Attributes\DataProvider;
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
final class RequestSigningTest extends TestCase
{
    private const string CONTEXT = 'signing-test-v1';
    private const string PATH = '/api/orders';
    private const string BODY = '{"item":"book"}';
    private const int NOW = 1753900000;
    private SharedKey $currentKey;
    private SharedKey $previousKey;
    private RequestVerifier $verifier;

    #[Override]
    protected function setUp(): void
    {
        $this->currentKey = new SharedKey();
        $this->previousKey = new SharedKey();
        $this->verifier = new RequestVerifier(
            (new KeyRing())->add('current', $this->currentKey)->add('previous', $this->previousKey),
            self::CONTEXT,
        );
    }

    public function testMatchesTheGoldenVectors(): void
    {
        $vectors = RequestSigningVectors::load();
        $key = new SharedKey($vectors['key']['sharedKey']);
        $keyId = $vectors['key']['keyId'];
        $context = $vectors['context'];
        $signer = new RequestSigner($keyId, $key, $context);
        $verifier = new RequestVerifier((new KeyRing())->add($keyId, $key), $context);

        self::assertSame($vectors['key']['sharedKeyHex'], bin2hex($key->getRawKey()));

        foreach ($vectors['requests'] as $vector) {
            $name = $vector['name'];
            $method = $vector['method'];
            $path = $vector['path'];
            $body = $vector['body'];
            $timestamp = $vector['timestamp'];

            self::assertSame($vector['bodySha256Hex'], hash('sha256', $body), $name);
            self::assertSame($vector['canonical'], CanonicalRequest::build($context, $method, $path, $timestamp, $body), $name);

            $signed = $signer->sign($method, $path, $body, (int) $timestamp);

            self::assertSame($timestamp, $signed->timestamp, $name);
            self::assertSame($vector['signature'], $signed->signature, $name);
            self::assertNull($verifier->verify($method, $path, $body, $keyId, $timestamp, $vector['signature'], (int) $timestamp), $name);
        }
    }

    public function testTheCanonicalStringHasFiveLinesAndNoTrailingLineFeed(): void
    {
        self::assertSame(
            "ctx\nPOST\n/p\n12\n" . hash('sha256', ''),
            CanonicalRequest::build('ctx', 'post', '/p', '12', ''),
        );
    }

    public function testAcceptsARequestSignedWithTheCurrentKey(): void
    {
        self::assertNull($this->verify($this->sign()));
    }

    public function testAcceptsARequestSignedWithThePreviousKey(): void
    {
        self::assertNull($this->verify($this->sign(keyId: 'previous', key: $this->previousKey)));
    }

    public function testAKeyIdSelectsItsOwnKeyOnly(): void
    {
        $signed = $this->sign(keyId: 'previous', key: $this->currentKey);

        self::assertSame(RequestVerificationFailure::BadSignature, $this->verify($signed));
    }

    public function testRejectsAnUnknownKeyId(): void
    {
        self::assertSame(RequestVerificationFailure::UnknownKeyId, $this->verify($this->sign(keyId: 'stranger')));
    }

    public function testAnEmptyRotationSlotCannotBeForgedAgainst(): void
    {
        $verifier = new RequestVerifier(KeyRing::fromPairs([['current', $this->currentKey->getKey()], ['', '']]), self::CONTEXT);
        $canonical = CanonicalRequest::build(self::CONTEXT, 'POST', self::PATH, (string) self::NOW, self::BODY);
        $forged = Base64::encode(hash_hmac(Mac::HASH_FUNCTION, $canonical, '', true));

        self::assertSame(
            RequestVerificationFailure::UnknownKeyId,
            $verifier->verify('POST', self::PATH, self::BODY, '', (string) self::NOW, $forged, self::NOW),
        );
    }

    public function testRejectsATamperedBody(): void
    {
        $signed = $this->sign();

        self::assertSame(
            RequestVerificationFailure::BadSignature,
            $this->verifier->verify('POST', self::PATH, '{"item":"yacht"}', $signed->keyId, $signed->timestamp, $signed->signature, self::NOW),
        );
    }

    public function testRejectsATamperedPath(): void
    {
        $signed = $this->sign();

        self::assertSame(
            RequestVerificationFailure::BadSignature,
            $this->verifier->verify('POST', '/api/refunds', self::BODY, $signed->keyId, $signed->timestamp, $signed->signature, self::NOW),
        );
    }

    public function testRejectsATamperedMethod(): void
    {
        $signed = $this->sign();

        self::assertSame(
            RequestVerificationFailure::BadSignature,
            $this->verifier->verify('DELETE', self::PATH, self::BODY, $signed->keyId, $signed->timestamp, $signed->signature, self::NOW),
        );
    }

    public function testTheMethodIsCaseInsensitive(): void
    {
        $signed = $this->sign();

        self::assertNull($this->verifier->verify('post', self::PATH, self::BODY, $signed->keyId, $signed->timestamp, $signed->signature, self::NOW));
    }

    public function testRejectsASignatureMadeUnderAnotherContext(): void
    {
        $signed = (new RequestSigner('current', $this->currentKey, 'another-context'))->sign('POST', self::PATH, self::BODY, self::NOW);

        self::assertSame(RequestVerificationFailure::BadSignature, $this->verify($signed));
    }

    #[DataProvider('provideTimestampsAtTheBoundary')]
    public function testTheWindowIsInclusiveOnBothSides(int $offset, ?RequestVerificationFailure $expected): void
    {
        self::assertSame($expected, $this->verify($this->sign(timestamp: self::NOW + $offset)));
    }

    /**
     * @return iterable<string, array{int, ?RequestVerificationFailure}>
     *
     * @psalm-mutation-free
     */
    public static function provideTimestampsAtTheBoundary(): iterable
    {
        yield 'exactly the window old' => [-300, null];
        yield 'one second older' => [-301, RequestVerificationFailure::StaleTimestamp];
        yield 'exactly the window ahead' => [300, null];
        yield 'one second further ahead' => [301, RequestVerificationFailure::StaleTimestamp];
    }

    public function testTheWindowIsConfigurable(): void
    {
        $verifier = new RequestVerifier((new KeyRing())->add('current', $this->currentKey), self::CONTEXT, 10);
        $signed = $this->sign(timestamp: self::NOW - 11);

        self::assertSame(
            RequestVerificationFailure::StaleTimestamp,
            $verifier->verify('POST', self::PATH, self::BODY, $signed->keyId, $signed->timestamp, $signed->signature, self::NOW),
        );
    }

    public function testAStaleTimestampUnderAWrongKeyIsABadSignature(): void
    {
        $signed = $this->sign(key: new SharedKey(), timestamp: 1000);

        self::assertSame(RequestVerificationFailure::BadSignature, $this->verify($signed));
    }

    public function testAnIdenticalRequestReplaysInsideTheWindow(): void
    {
        $signed = $this->sign();

        self::assertNull($this->verify($signed));
        self::assertNull($this->verify($signed, self::NOW + 299));
        self::assertSame(RequestVerificationFailure::StaleTimestamp, $this->verify($signed, self::NOW + 301));
    }

    public function testRejectsMissingFields(): void
    {
        $signed = $this->sign();

        self::assertSame(RequestVerificationFailure::MissingFields, $this->verifier->verify('POST', self::PATH, self::BODY, null, $signed->timestamp, $signed->signature, self::NOW));
        self::assertSame(RequestVerificationFailure::MissingFields, $this->verifier->verify('POST', self::PATH, self::BODY, $signed->keyId, null, $signed->signature, self::NOW));
        self::assertSame(RequestVerificationFailure::MissingFields, $this->verifier->verify('POST', self::PATH, self::BODY, $signed->keyId, $signed->timestamp, null, self::NOW));
    }

    #[DataProvider('provideMalformedTimestamps')]
    public function testRejectsAMalformedTimestamp(string $timestamp): void
    {
        $signed = $this->sign();

        self::assertSame(
            RequestVerificationFailure::MalformedField,
            $this->verifier->verify('POST', self::PATH, self::BODY, $signed->keyId, $timestamp, $signed->signature, self::NOW),
        );
    }

    /**
     * @return iterable<string, array{string}>
     *
     * @psalm-mutation-free
     */
    public static function provideMalformedTimestamps(): iterable
    {
        yield 'empty' => [''];
        yield 'a leading zero' => ['01753900000'];
        yield 'a short leading zero' => ['0123'];
        yield 'eleven digits' => ['17539000000'];
        yield 'signed' => ['+1753900000'];
        yield 'negative' => ['-1'];
        yield 'decimal' => ['1753900000.0'];
        yield 'padded' => [' 1753900000'];
        yield 'a trailing line feed' => ["1753900000\n"];
        yield 'hexadecimal' => ['0x6889'];
    }

    #[DataProvider('provideMalformedSignatures')]
    public function testRejectsAMalformedSignature(string $signature): void
    {
        $signed = $this->sign();

        self::assertSame(
            RequestVerificationFailure::MalformedField,
            $this->verifier->verify('POST', self::PATH, self::BODY, $signed->keyId, $signed->timestamp, $signature, self::NOW),
        );
    }

    /**
     * @return iterable<string, array{string}>
     *
     * @psalm-mutation-free
     */
    public static function provideMalformedSignatures(): iterable
    {
        yield 'empty' => [''];
        yield 'not Base64' => ['!!! not base64 !!!'];
        yield 'too short' => [Base64::encode(str_repeat('a', Mac::MAC_SIZE - 1))];
        yield 'too long' => [Base64::encode(str_repeat('a', Mac::MAC_SIZE + 1))];
    }

    public function testAPathWithALineBreakIsMalformedNotAnException(): void
    {
        $signed = $this->sign();

        self::assertSame(
            RequestVerificationFailure::MalformedField,
            $this->verifier->verify('POST', "/api/orders\nGET", self::BODY, $signed->keyId, $signed->timestamp, $signed->signature, self::NOW),
        );
    }

    public function testTheTimestampDefaultsToNow(): void
    {
        $signed = (new RequestSigner('current', $this->currentKey, self::CONTEXT))->sign('GET', self::PATH);

        self::assertEqualsWithDelta(time(), (int) $signed->timestamp, 5);
        self::assertNull($this->verifier->verify('GET', self::PATH, '', $signed->keyId, $signed->timestamp, $signed->signature));
    }

    public function testTheSignerRefusesALineBreak(): void
    {
        $this->expectException(RequestSigningException::class);

        (new RequestSigner('current', $this->currentKey, self::CONTEXT))->sign('POST', "/api\r\n/orders");
    }

    public function testTheSignerRefusesAnEmptyKeyId(): void
    {
        $this->expectException(RequestSigningException::class);

        new RequestSigner('', $this->currentKey, self::CONTEXT);
    }

    public function testTheSignerRefusesAnEmptyContext(): void
    {
        $this->expectException(RequestSigningException::class);

        new RequestSigner('current', $this->currentKey, '');
    }

    public function testTheSignerRefusesATimestampItCannotWrite(): void
    {
        $this->expectException(RequestSigningException::class);

        (new RequestSigner('current', $this->currentKey, self::CONTEXT))->sign('GET', self::PATH, '', 10_000_000_000);
    }

    public function testTheSignerRefusesANegativeTimestamp(): void
    {
        $this->expectException(RequestSigningException::class);

        (new RequestSigner('current', $this->currentKey, self::CONTEXT))->sign('GET', self::PATH, '', -1);
    }

    public function testTheVerifierRefusesAnEmptyContext(): void
    {
        $this->expectException(RequestSigningException::class);

        new RequestVerifier(new KeyRing(), '');
    }

    public function testTheVerifierRefusesAWindowThatIsNotPositive(): void
    {
        $this->expectException(RequestSigningException::class);

        new RequestVerifier(new KeyRing(), self::CONTEXT, 0);
    }

    private function sign(string $keyId = 'current', ?SharedKey $key = null, int $timestamp = self::NOW): SignedRequest
    {
        return (new RequestSigner($keyId, $key ?? $this->currentKey, self::CONTEXT))->sign('POST', self::PATH, self::BODY, $timestamp);
    }

    private function verify(SignedRequest $signed, int $now = self::NOW): ?RequestVerificationFailure
    {
        return $this->verifier->verify('POST', self::PATH, self::BODY, $signed->keyId, $signed->timestamp, $signed->signature, $now);
    }
}
