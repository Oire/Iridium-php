# Version 3.1

## Security

* **`SplitToken::fromString()` now rejects expired and revoked tokens.**
  Previously it read the expiration into the object and returned successfully regardless, leaving
  the check to the caller. Since `revokeToken()` records a revocation *as* an expiration in the
  past, the default outcome for a caller who did not know to call `isExpired()` was that a revoked
  token authenticated. If you relied on the old behavior to report on a dead token, pass the new
  `allowExpired: true` argument — but never to authenticate:

  ```php
  // Before (v3.0) — a revoked token got through unless you remembered this check
  $splitToken = SplitToken::fromString($token, $storage);

  if ($splitToken->isExpired()) {
      throw new RuntimeException('Expired');
  }

  // After (v3.1) — InvalidTokenException is thrown for you
  $splitToken = SplitToken::fromString($token, $storage);
  ```

  Audit any code that calls `fromString()` without an `isExpired()` check afterwards: until now it
  accepted revoked tokens.

## Changes

* **`SplitToken::revokeBySelector()`**, a static counterpart to `revokeToken()`.
  `revokeToken()` needs an instance, and the only way to obtain one is `fromString()`, which needs
  the plaintext token — precisely what the owner of a long-lived token no longer has, having been
  shown it once. Revoking an API key from a management screen was therefore impossible through the
  public API.
* **`SplitToken::getSelector()`**. The selector is the public half of the token and the key to every
  stored-token operation, but the object that had just validated one would not tell you what it was,
  so consumers had to recompute it from the plaintext.
* **`ListableTokenStorageInterface`**, an optional extension of `TokenStorageInterface` adding
  `findByUserId()`, `findBySelector()`, `touch()` and `clearExpiredBefore()`, along with the
  `StoredToken` value object. `TokenStorageInterface` could not enumerate a user's tokens, which any
  personal-access-token management UI needs. Both bundled storages implement it; it requires two
  further columns, `created_at` and `last_used_at` — see the README.
* **`DoctrineDbalTokenStorage`**, a Doctrine DBAL storage implementation. `doctrine/dbal` is a
  development and suggested dependency only, so the library stays dependency-free.
* **`clearExpiredBefore()`** takes a cutoff, unlike `clearExpired()`, which uses the current time and
  therefore also erases tokens revoked seconds ago. Passing `time() - 90 * 86400` keeps a quarter of
  revocation history to audit.
* **`SplitToken::EXPIRATION_DEFAULT`** names the magic `0` that means "expire in one hour". A bare
  `0` reads like "no expiration" and silently gives an hour instead; `null` is what makes a token
  eternal.

# Version 3.0

## Breaking changes when upgrading from 2.x

* **PHP 8.3+ required** (was 8.2+).
* **License changed from MIT to Apache-2.0.**
* **Encryption**: `Crypt::encrypt()` now produces AES-256-GCM ciphertext (v2 format).
  `Crypt::decrypt()` transparently handles both v2 and legacy v1 (AES-256-CTR + HMAC-SHA384) ciphertext,
  so existing encrypted data can still be decrypted without changes.
* **`SplitToken` now accepts `TokenStorageInterface` instead of `PDO`.**
  Wrap your PDO instance in the provided `PdoTokenStorage` adapter:
  ```php
  // Before (v2.x)
  $token = SplitToken::create($pdo);

  // After (v3.0)
  use Oire\Iridium\Storage\PdoTokenStorage;

  $storage = new PdoTokenStorage($pdo);
  $token = SplitToken::create($storage);
  ```

## Changes

* [#100](https://github.com/Oire/Iridium-php/pull/100):
  Modernize code and add AES-256-GCM authenticated encryption (v2 cipher scheme).
  Legacy v1 AES-256-CTR + HMAC-SHA384 decryption is preserved for backward compatibility.
  Extract `TokenStorageInterface` and `PdoTokenStorage` for split token persistence.
  Use readonly constructor promotion, static factory methods on exceptions, and other PHP 8.3+ features throughout.
* [#99](https://github.com/Oire/Iridium-php/pull/99):
  Dockerize local development and CI with FrankenPHP and MariaDB.
* [#98](https://github.com/Oire/Iridium-php/pull/98):
  Change license to Apache-2.0. Update copyright to Oire Software.
* [#95](https://github.com/Oire/Iridium-php/pull/95):
  Require PHP 8.3 or later. Update copyright year to 2025.
* Dependency updates:
  [#96](https://github.com/Oire/Iridium-php/pull/96),
  [#97](https://github.com/Oire/Iridium-php/pull/97),
  [#101](https://github.com/Oire/Iridium-php/pull/101).

# Version 2.0

* [#94](https://github.com/Oire/Iridium-php/pull/94):
  Refactor `SplitToken` to use a private constructor with `create()` and `fromString()` static factory methods.
  Remove setters. Eternal tokens now have `null` expiration time; `0` means default (one hour).
* [#93](https://github.com/Oire/Iridium-php/pull/93):
  Require PHP 8.2 or later. Remove CaptainHook.
* [#76](https://github.com/Oire/Iridium-php/pull/76):
  Change default token expiration time to one hour.
* Remove deprecated `SymmetricKey` and `Osst` classes.
* Remove deprecated `tokenIsExpired()` method.

# Version 1.2

* [#75](https://github.com/Oire/Iridium-php/pull/75):
  Deprecate `Osst` in favor of `SplitToken`.
* [#53](https://github.com/Oire/Iridium-php/pull/53):
  Deprecate `SymmetricKey` in favor of `SharedKey`.
* [#52](https://github.com/Oire/Iridium-php/pull/52):
  Add release notes configuration. Add PHP CodeSniffer to GitHub Actions CI.

# Version 1.1

* [#43](https://github.com/Oire/Iridium-php/pull/43):
  Add basic PHP CodeSniffer ruleset. Add typed properties.
* [#27](https://github.com/Oire/Iridium-php/pull/27):
  Wrap internal derived keys into a `DerivedKeys` value object.
* [#20](https://github.com/Oire/Iridium-php/pull/20):
  Add [Captain Hook](https://github.com/captainhookphp/captainhook) support.
* [#19](https://github.com/Oire/Iridium-php/pull/19):
  Add eternal tokens (tokens that never expire until revoked manually).
* Drop support for PHP 7.3; require PHP 7.4 or later.
* Deprecate `tokenIsExpired()` in favor of `isExpired()`.

# Version 1.0

Initial release.