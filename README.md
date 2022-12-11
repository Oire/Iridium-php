# Iridium, a Security Library for Encrypting Data, Hashing Passwords and Managing Secure Tokens

[![Latest Version on Packagist](https://img.shields.io/packagist/v/Oire/Iridium.svg?style=flat-square)](https://packagist.org/packages/Oire/Iridium)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/Oire/Iridium-php/blob/master/LICENSE)
[![Psalm coverage](https://shepherd.dev/github/Oire/Iridium-php/coverage.svg?)
[![Psalm level](https://shepherd.dev/github/Oire/Iridium-php/level.svg?)](https://psalm.dev/)

Welcome to Iridium, a security library for encrypting data, hashing passwords and managing secure tokens!  
This library consists of several classes, or modules, and can be used for hashing and verifying passwords, encrypting and decrypting data, as well as for managing secure tokens suitable for authentication cookies, password reset, API access and various other tasks.

## Requirements

Requires PHP 7.4 or later with _PDO_, _Mbstring_ and _OpenSSL_ enabled.

## Installation

Install via [Composer](https://getcomposer.org/):

```shell
composer require oire/iridium
```

## Running Tests

Run `./vendor/bin/phpunit` in the project directory.

## Running Psalm Analysis

Run `./vendor/bin/psalm` in the project directory.

## 🖇 Base64 Handling, URL-safe Way

The Base64 module encodes data to Base64 URL-safe way and decodes encoded data.

### Usage Examples

```php
use Oire\Iridium\Base64;
use Oire\Iridium\Exception\Base64Exception;

$text = "The quick brown fox jumps over the lazy dog";
$encoded = Base64::encode($text);
echo $encoded.PHP_EOL;
```

This will output:  

```shell
VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw
```

By default, the `encode()` method truncates padding `=` signs as PHP’s built-in decoder handles this correctly. However, if the second parameter is given and set to `true`, `=` signs will be replaced with tildes (`~`), i.e.:

```php
$encoded = Base64::encode($text, true);
echo $encoded.PHP_EOL;
````

This will output:  

```shell
VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw~~
```

To decode the data, simply call `Base64::decode()`:

```php
$encoded = "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw";

try {
    $decoded = Base64::decode($encoded);
} catch(Base64Exception $e) {
    // Handle errors
}

echo $decoded.PHP_EOL;
```

This will output:  

```shell
The quick brown fox jumps over the lazy dog
```

### Methods

The Base64 class has the following methods:

* `static encode(string $data, bool $preservePadding = false): string` — Encodes provided data into URL-safe Base64. If `preservePadding` is set to `true`, the padding `=` signs will be replaced by tildes (`~`). If set to `false` (default), padding signs will be truncated.
* `static decode(string $encodedData): string` — decodes provided Base64 data and returns the original string.

## 🗝 Crypt

The Crypt module is used to encrypt and decrypt data.  
**Note**! Do not use this for managing passwords! Passwords must not be encrypted, they must be *hashed* instead. To manage passwords, use the Password module (see below).  
Currently the Crypt module supports only shared key encryption, i.e., encryption and decryption is performed with one single key.

### Shared Key

**Note**! the `SymmetricKey` class is deprecated since version 1.2 and will be removed in version 2.0. It holds the same object but was renamed to `SharedKey` for simplicity.
This objects holds a key used to encrypt and decrypt data with the Crypt module. First you need to create a key and save it somewhere (i.e., in a .env file):

```php
use Oire\Iridium\Key\SharedKey;

$sharedKey = new SharedKey();
$key = $sharedKey->getKey();
// Save the key instead
echo $key . PHP_EOL;
```

This will output a readable and storable string, something similar to this:

```shell
AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8
```

#### SharedKey Methods

Generally, you will only need the `getKey()` method for storing the key in a safe place. You can also benefit from using the `__toString()` method and treat the key object as a string. However, let’s describe all the methods for the sake of completeness:

* `__construct(string|null $key = null)` — Class constructor. If a key is provided, it will be applied to create a new SharedKey instance. If not, a random key will be generated instead.
* `getRawKey(): string` — Returns the key in raw binary form. Needed mostly for internal use.
* `getKey(): string` — Returns the key in readable and storable form. Use this to retrieve a newly generated random key.
* `deriveKeys(string|null $salt = null): DerivedKeys` — Uses [hash key derivation function](https://en.wikipedia.org/wiki/HKDF) to derive encryption and authentication keys and returns a `DerivedKeys` object, see below. Use this only if you really know what you are doing. It is used internally by the Crypt module. If the salt is provided, derives the keys based on that salt (used for decryption). In 99,(9)% of cases you don’t need to use this method directly.
* `__toString(): string` — Returns the readable and storable key when the object is called as a string.

### Derived Keys

The DerivedKeys object holds the keys derived by the `deriveKeys()` method of the shared key. Again, in 99,(9)% of cases you don’t want to use it, but let’s enumerate its methods.

* `__construct(string $salt, string $encryptionKey, string $authenticationKey)` — Class constructor. Is instantiated by the `deriveKeys()` method of the `SharedKey` object.
* `getSalt(): string` — Gets the encryption salt.
* `getEncryptionKey(): string` — Gets the derived encryption key.
* `getAuthenticationKey(): string` — Gets the derived authentication key.
* `areValid(): bool` — Checks if the derived keys are valid. Returns `true` if the keys are valid, `false` otherwise.

### Crypt Usage Examples

If you created a shared key as shown above, you can encrypt your data with this key:

```php
use Oire\Iridium\Crypt;
use Oire\Iridium\Key\SharedKey;

$data = 'Mischief managed!';
$sharedKey = new SharedKey($key);
$encrypted = Crypt::encrypt($data, $sharedKey);
```

That's it, you may store your encrypted data in a database or perform other actions with them.  
To decrypt the data with the same key, use the following:

```php
$decrypted = Crypt::decrypt($encrypted, $sharedKey);
```

### Exceptions
Crypt throws `EncryptionException`, `DecryptionException` and sometimes a more general `CryptException`. If something is wrong with the key, a `SharedKeyException` is thrown.

### Methods

The Crypt class has the following methods:

* `static encrypt(string $data, SharedKey $key): string` — Encrypts given data with a given key. Returns the encrypted data in readable and storable form.
* `static Decrypt(string $encryptedData, SharedKey $key): string` — Decrypts previously encrypted data with the same key they were encrypted with and returns the original string.
* `static swapKey(string $data, SharedKey $oldKey, SharedKey $newKey): string` — Reencrypts encrypted data with a different key and returns the newly encrypted data.

## 🔒 Password

The Password class is used to hash passwords and verify that a provided hash is valid.

### Usage Examples

To lock, i.e., hash a password, use the following:

```php
use Oire\Iridium\Exception\PasswordException;
use Oire\Iridium\Key\SharedKey;
use Oire\Iridium\Password;

// You should have $key somewhere in an environment variable
$sharedKey = new SharedKey($key);

try {
    $storeMe = Password::lock($_POST['password'], $sharedKey);
} catch (PasswordException $e) {
    // Handle errors
}
```

Then you can store your password in the database.  
To check whether a provided password is valid, use the following:

```php
try {
    $isPasswordValid = Password::check($_POST['password'], $hashFromDatabase, $sharedKey);
} catch (PasswordException $e) {
    // Handle errors. Something went wrong: most often it's a wrong or corrupted key
}

if ($isPasswordValid) {
    // OK
} else {
    // Wrong password
}
```

You can also use Crypt to reencrypt the password with another key, just use `Crypt::swapKey()` and provide your password hash to it.  
Remember that you cannot "decrypt" a password and obviously must not store unhashed plain-text passwords, this poses a huge security risk.

### Methods

The Password class has the following methods:

* `static Lock(string $password, SharedKey $key): string` — Locks, i.e., hashes a password and encrypts it with a given key. Returns the encrypted hash in readable and storable format. A hashed password cannot be restored, so it is safe to be stored in a database.
* `static Check(string $password, string $encryptedHash, SharedKey $key): bool` — Verifies whether a given password matches the provided hash. Returns `true` on success and `false` on failure.

## 🍪 SplitToken, Simple Yet Secure Token Suitable for Authentication Cookies and Password Recovery

**Note**! the `Osst` class is deprecated since version 1.2 and will be removed in version 2.0. It holds the same object but was renamed to `SplitToken` for simplicity.

SplitToken is a class inside Iridium that can be used for generating and validating secure tokens suitable for authentication cookies, password recovery, API keys and various other tasks.  

### The Split Tokens Concept

You can read everything about the split tokens authentication in [this 2017 article](https://paragonie.com/blog/2017/02/split-tokens-token-based-authentication-protocols-without-side-channels) by [Paragon Initiatives](https://paragonie.com). Iridium implements the idea outlined in that article in PHP.

### Usage Examples

SplitToken uses fluent interface, i.e., all necessary methods can be chained.  
Each time you instantiate a new SplitToken object, you need to provide a database connection as a PDO instance. If you don’t use PDO yet, consider using it, it’s convenient. If you use an ORM, you most likely have a `getPdo()` or a similar method.  
Support for popular ORMs is planned for a future version.

#### Create a Table

Iridium tries to be as database agnostic as possible (MySQL and SQLite were tested, the latter actually powers the tests).  
First you need to create the `iridium_tokens` table. For mySQL the statement is as follows:

```sql
CREATE TABLE `iridium_tokens` (
    `id` INT UNSIGNED NULL AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT UNSIGNED NOT NULL,
    `token_type` INT NULL ,
    `selector` VARCHAR(25) NOT NULL,
    `verifier` VARCHAR(70) NOT NULL,
    `additional_info` TEXT(300) NULL,
    `expiration_time` BIGINT(20) UNSIGNED NOT NULL,
    UNIQUE `token` (`selector`, `verifier`),
    CONSTRAINT `fk_token_user_id`
        FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
        ON DELETE CASCADE
        ON UPDATE RESTRICT
) ENGINE = InnoDB;
```

You may need to adjust the syntax to suit your particular database driver (see for example the SQLite statement in the tests), as well as the name of your `users` table.  
The field lengths are optimal, the only one you may need to adjust is `additional_info`, if you are planning to use it for larger sets of data.

#### Create a Token

First you need to create a token. There are some **required** properties marked in bold and some *optional* ones marked in italic you can set. If you don’t set one or more of the required properties, a `SplitTokenException` will be thrown.

* `userId`, **required** — ID of the user the token belongs to, as an unsigned integer.
* `expirationTime`, *optional* — Time when the token expires. Stored as timestamp (big integer), but can be set in various ways, see below. If not set or set to `0`, the token is eternal, i.e., it never expires.
* `tokenType`, *optional* — If you want to perform an additional check of the token (say, separate password recovery tokens from e-mail change tokens), you may set a token type as an integer. In the examples throughout this file we’ll use plain numbers, but we suggest using constants or enums instead.
* `additionalInfo`, *optional* — Any additional information you want to convey with the token, as string. For instance, you can pass some JSON data here. The information can be additionally encrypted, see below.

To create a token for user with ID of `123` and with token type of `3` expiring in an hour, and store it into the database, do the following:

```php
use Oire\Iridium\SplitToken;

// You should have set your $dbConnection first as a PDO instance
$splitToken = (new SplitToken($dbConnection))
    ->setUserId(123)
    ->setExpirationTime(time() + 3600)
    ->setTokenType(3)
    ->setAdditionalInfo('{"some": "data"}')
    ->persist();
```

Use `$splitToken->getToken()` to actually get the newly created token as a string.  
If you want to create a non-expirable token, either use `makeEternal()` instead of `setExpirationTime()` for code readability, or skip this call altogether.

#### Set and Validate a User-Provided Token

If you received an Iridium token from the user, you also need to instantiate SplitToken and validate the token. You don't need to set all the properties as their values are taken from the database.

```php
use Oire\Iridium\Exception\InvalidTokenException;
use Oire\Iridium\SplitToken;

try {
    $splitToken = new SplitToken($dbConnection, $token);
} catch (InvalidTokenException $e) {
    // Something went wrong with the token: either it is invalid, not found or has been tampered with
}

if ($splitToken->isExpired()) {
    // The token is correct but expired
}
```

**Note**! An expired token is considered settable, i.e., not valid per se but correct, so no exception is thrown in this case, you have to check it manually as shown above. If this behavior is non-intuitive or inconvenient, please [create a Github issue](https://github.com/Oire/Iridium-php/issues/new).

#### Revoke a Token

After a token is used once for authentication, password reset and other sensitive operation, is expired or compromised, you must revoke, i.e., invalidate it. If you use Iridium tokens as API keys, tokens for unsubscribing from email lists and so on, you can make your token eternal or set the expiration time far in the future and not revoke the token after first use, certainly. If an eternal token is compromised, you must revoke it, also. There are two ways of revoking a token:

* Setting the expiration time for the token in the past (default);
* Deleting the token from the database whatsoever. To do this, pass `true` as the parameter to the `revokeToken()` method:

```php
// Given that $splitToken contains a valid token
$splitToken->revokeToken(true);
```

#### Clear Expired Tokens

From time to time you will need to delete all expired tokens from the database to reduce the table size and search times. There is a method to do this. It is static, so you have to provide your PDO instance as its parameter. It returns the number of tokens deleted from the database.

```php
$deletedTokens = SplitToken::clearExpiredTokens($dbConnection);
```

#### Three Ways of Setting Expiration Time

You may set expiration time in three different ways, as you like:

* `setExpirationTime()` — Accepts a raw timestamp as integer. If set to `null` or `0`, the token is eternal and never expires.
* `setExpirationDate()` — Accepts a `DateTimeImmutable` object.
* `setExpirationOffset()` — Accepts a [relative datetime format](https://www.php.net/manual/en/datetime.formats.relative.php). Default is `+14 days`.

#### Notes on Expiration Times

* All expiration times are internally stored as UTC timestamps.
* Expiration times are set, compared and formatted according to the time of the PHP server, so you won't be in trouble even if your PHP and database server times are different for some reason.
* Expiration time with value `0` makes your token eternal, so it never expires until you revoke it manually.
* Microseconds for expiration times are ignored for now, their support is planned for a future version.

#### Encrypt Additional Information

You may store some sensitive data in the additional information for the token such as old and new e-mail address and similar things.  
**Note**! Do **not** store plain-text passwords in this property, it can be decrypted! Passwords must not be decryptable, they must be *hashed* instead. If you need to handle passwords, use the Password class, it is suitable for proper password hashing (see above). You may store password hashes in this property, though.  
If your additional info contains sensitive data, you can encrypt it. To do this, you first need to have an Iridium key (see above):

```php
use Oire\Iridium\Key\SharedKey;
use Oire\Iridium\SplitToken;

$key = new SharedKey();
// Store the key somewhere safe, i.e., in an environment variable. You can safely cast it to string for that (see above)
$additionalInfo = '{"oldEmail": "john@example.com", "newEmail": "john.doe@example.com"}';
$splitToken = (new SplitToken($dbConnection))
    ->setUserId($user->getId())
    ->setExpirationOffset('+30 minutes')
    ->setTokenType(self::TOKEN_TYPE_CHANGE_EMAIL)
    ->setAdditionalInfo($additionalInfo, $key)
    ->persist();
```

That's it. I.e., if the second parameter of `setAdditionalInfo()` is not empty and is a valid Iridium key, your additional information will be encrypted. If something is wrong, a `SplitTokenException` will be thrown.  
If you received a user-provided token whose additional info is encrypted, pass the key as the third parameter to the SplitToken constructor.

### Error Handling

SplitToken throws two types of exceptions:

* `InvalidTokenException` is thrown when something really wrong happens to the token itself or to SQL queries related to the token (for example, a token is not found, it has been tampered with, its length is invalid or a PDO statement cannot be executed);
* `SplitTokenException` is thrown in most cases when you do something erroneously (for example, try to store an empty token into the database, forget to set a required property or try to set such a property when validating a user-provided token, try to set expiration time which is in the past etc.).

### Methods

Below all of the SplitToken methods are outlined.

* `__construct(PDO $dbConnection, string|null $token, Oire\Iridium\Key\SharedKey|null $additionalInfoDecryptionKey)` — Instantiate a new SplitToken object. Provide a PDO instance as the first parameter, the user-provided token as the second one, and the Iridium key for decrypting additional info as the third one. **Note**! Provide the token only if you received it from the user. If you want to create a fresh token, the second and third parameters must not be set.
* `getDbConnection(): PDO` — Get the database connection for the current SplitToken instance as a PDO object.
* `getToken(): string` — Get the token for the current SplitToken instance as a string. Throws `SplitTokenException` if the token was not created or set before.
* `getUserId(): int` — Get the ID of the user the token belongs to, as an integer.
* `setUserId(int $userId): self` — Set the user ID for the newly created token. Do not use this method and similar methods when validating a user-provided token, use them only when creating a new token. Returns `$this` for chainability.
* `getExpirationTime(): int` — Get expiration time for the token as raw timestamp. Returns integer.
* `getExpirationDate(): DateTimeImmutable` — Get expiration time for the token as a DateTimeImmutable object. Returns the date in the current time zone of your PHP server.
* `getExpirationDateFormatted(string $format = 'Y-m-d H:i:s'): string` — Get expiration time for the token as date string. The default format is `2020-11-15 12:34:56`. The `$format` parameter must be a valid [date format](https://www.php.net/manual/en/function.date.php).
* `setExpirationTime(int|null $timestamp = null): self` — Set expiration time for the token as a raw timestamp. If the timestamp is set to `null` or `0`, the token never expires.
* `makeEternal(): self` — A convenience method that makes the token eternal, so it will never expire until you revoke it manually. Returns `$this` for chainability.
* `setExpirationOffset(string $offset = '+14 days'): self` — Set expiration time for the token as a relative time offset. The default value is `+14 days`. The `$offset` parameter must be a valid [relative time format](https://www.php.net/manual/en/datetime.formats.relative.php). Returns `$this` for chainability.
* `setExpirationDate(DateTimeImmutable $expirationDate): self` — Set expiration time for the token as a [DateTimeImmutable](https://www.php.net/manual/en/class.datetimeimmutable.php) object. Returns `$this` for chainability.
* `isEternal(): bool` — check if the token is eternal and never expires. Returns `true` if the token is eternal, `false` if it has expiration time set in the future or already expired.
* `isExpired(): bool` — Check if the token is expired. Returns `true` if the token has already expired, `false` otherwise.
* `getTokenType(): int|null` — Get the type for the current token. Returns integer if the token type was set before, or null if the token has no type.
* `setTokenType(int|null $tokenType): self` — Set the type for the current token, as integer or null. Returns `$this` for chainability.
* `getAdditionalInfo(): string|null` — Get additional info for the token. Returns string or null, if additional info was not set before.
* `setAdditionalInfo(string|null $additionalInfo, Oire\Iridium\Key\SharedKey|null $encryptionKey = null): self` — Set additional info for the current token. If the `$encryptionKey` parameter is not empty, tries to encrypt the additional information using the Crypt class. Returns `$this` for chainability.
* `persist(): self` — Store the token into the database. Returns `$this` for chainability.
* `revokeToken(bool $deleteToken = false): void` — Revoke. i.e., invalidate the current token after it is used. If the `$deleteToken` parameter is set to `true`, the token will be deleted from the database, and `getToken()` will return `null`. If it is set to `false` (default), the expiration time for the token will be updated and set to a value in the past. The method returns no value.
* `static clearExpiredTokens(PDO $dbConnection): int` — Delete all expired tokens from the database. As it is a static method, it receives the database connection as a PDO object. Returns the number of deleted tokens, as integer.

## Changes and Bugfixes

See [changelog](https://github.com/Oire/Iridium-php/blob/master/CHANGELOG.md).

## Contributing

All contributions are welcome. Please fork, make a feature branch, do `composer install`, hack on the code, commit, push your branch and send a pull request.

Before committing, don’t forget to run all the needed checks, otherwise the CI will complain afterwards:

```shell
./vendor/bin/phpunit
./vendor/bin/psalm
./vendor/bin/php-cs-fixer fix
./vendor/bin/phpcs .
```

If PHPCodeSniffer finds any code style errors, fix them in your code.  
When your pull request is submitted, make sure all checks passed on CI.

## License

Copyright © 2021-2022 Andre Polykanine also known as Menelion Elensúlë, [The Magical Kingdom of Oirë](https://github.com/Oire/).  
This software is licensed under an MIT license.
