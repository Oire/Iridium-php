# Iridium, a Security Library for Encrypting Data, Hashing Passwords and Managing Secure Tokens

[![Latest Version on Packagist](https://img.shields.io/packagist/v/Oire/Iridium.svg?style=flat-square)](https://packagist.org/packages/Oire/Iridium)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/Oire/Iridium-php/blob/master/LICENSE)
[![Psalm coverage](https://shepherd.dev/github/Oire/Iridium-php/coverage.svg?)
[![Psalm level](https://shepherd.dev/github/Oire/Iridium-php/level.svg?)](https://psalm.dev/)

Welcome to Iridium, a security library for encrypting data, hashing passwords and managing secure tokens!  
This library consists of several classes, or modules, and can be used for hashing and verifying passwords, encrypting and decrypting data, as well as for managing secure tokens suitable for authentication cookies, password reset, API access and various other tasks.

## Requirements

Requires PHP 8.1 or later with _PDO_, _Mbstring_ and _OpenSSL_ enabled.

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

### 🔑 Shared Key

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

SplitToken is a class inside Iridium that can be used for generating and validating secure tokens suitable for authentication cookies, password recovery, API keys and various other tasks.  

### The Split Tokens Concept

You can read everything about the split tokens authentication in [this 2017 article](https://paragonie.com/blog/2017/02/split-tokens-token-based-authentication-protocols-without-side-channels) by [Paragon Initiatives](https://paragonie.com). Iridium implements the idea outlined in that article in PHP.

### Usage Examples

Each time you use `SplitToken::create()` to generate a new token or `SplitToken::fromString()` to instantiate a new SplitToken object from a user-provided token, you need to provide a database connection as a PDO instance. If you don’t use PDO yet, consider using it, it’s convenient. If you use an ORM, you most likely have a `getPDO()` or a similar method.  
Support for popular ORMs is planned for a future version.

#### Create a Table

Iridium tries to be as database agnostic as possible (MySQL and SQLite were tested, the latter actually powers the tests).  
First you need to create the `iridium_tokens` table. For mySQL the statement is as follows:

```sql
CREATE TABLE `iridium_tokens` (
    `id` INT UNSIGNED NULL AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT UNSIGNED NULL,
    `token_type` TINYINT UNSIGNED NULL ,
    `selector` VARCHAR(25) NOT NULL,
    `verifier` VARCHAR(70) NOT NULL,
    `additional_info` TEXT NULL,
    `expires_at` BIGINT(20) UNSIGNED NULL,
    CONSTRAINT `fk_iridium_token_user`
        FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
        ON UPDATE RESTRICT
        ON DELETE CASCADE
) ENGINE = InnoDB;
```

You may need to adjust the syntax to suit your particular database driver (see for example the SQLite statement in the tests), as well as the name of your `users` table.  
The field lengths are optimal. Please remember though, that you need to adjust the length and sign (`UNSIGNED` or not) of the `user_id` field in the `FOREIGN KEY` constraint, otherwise you’ll get very cryptic errors from MySQL or MariaDB.

#### Create a Token

First you need to create a token. There are some parameters you can set, but only the database connection is required, all the other parameters have default values.

* `dbConnection` — Database connection, as a PDO instance.
* `expirationTime` — Time when the token expires. Stored as timestamp (big integer), but can be set either as an integer or as a string. If you provide a string, it will be fed to the `DateTimeImmutable` constructor. There is also a special value `0` (zero). If you set the expiration time to 0, the default expiration time will be used, it is equal to current time plus one hour. If `expirationTime` is set to `null`, the token is eternal, i.e., it never expires. The default value is `0`, i.e., expiration in one hour.
* `userId` — ID of the user the token belongs to, as an unsigned integer. If it is set and is 0 or less, an exception will be thrown.
* `tokenType` — If you want to perform an additional check of the token (say, separate password recovery tokens from e-mail change tokens), you may set a token type as an integer. In the examples throughout this file we’ll use plain numbers, but we suggest using an enum instead.
* `additionalInfo` — Any additional information you want to convey with the token, as string. For instance, you can pass some JSON data here. The information can be additionally encrypted. **Note again!** Do not use this to store passwords, even obsolete ones, this can be decrypted.
* `additionalInfoKey` — an Iridium shared key used to encrypt the additional info. 

To create a token for user with ID of `123` and with token type of `3` expiring in half an hour, and store it into the database, do the following. You can of course use named arguments:

```php
use Oire\Iridium\SplitToken;

// You should have set your $dbConnection first as a PDO instance
$splitToken =  SplitToken::create(
        dbConnection: $dbConnection,
        expirationTime: time() + 1800,
        userId: 123,
        tokenType: 3,
        additionalInfo: '{"some": "data"}
    )
    ->persist();
```

Use `$splitToken->getToken()` to actually get the newly created token as a string.  
If you want to create a non-expirable token, explicitly set `expirationTime` to `null`.

#### Set and Validate a User-Provided Token

If you received an Iridium token from the user, you also need to instantiate SplitToken and validate the token. To do this, use `SplitToken::fromString()` instead of `create()`. You don't need to set all the properties as their values are taken from the database.  
This method takes three parameters: database connection as PDO instance, the token as string, and optionally the additional info decryption key as Iridium shared key.

```php
use Oire\Iridium\Exception\InvalidTokenException;
use Oire\Iridium\SplitToken;

try {
    $splitToken = SplitToken::fromString($token, $dbConnection);
} catch (InvalidTokenException $e) {
    // Something went wrong with the token: either it is invalid, not found or has been tampered with
}

if ($splitToken->isExpired()) {
    // The token is correct but expired
}
```

**Note**! An expired token is considered settable, i.e., not valid per se but correct, so no exception is thrown in this case, you have to check it manually as shown above. If this behavior is non-intuitive or inconvenient, please [create a Github issue](https://github.com/Oire/Iridium-php/issues/new).

#### Revoke a Token

After a token is used once for authentication, password reset and other sensitive operation, is expired or compromised, you must revoke, i.e., invalidate it. If you use Iridium tokens as API keys, tokens for unsubscribing from email lists and so on, you can make your token eternal or set the expiration time far in the future and not revoke the token after first use, certainly. If an eternal token is compromised, you must revoke it, also. The `revokeToken()` method returns a `SplitToken` instance with the token-related parameters set to `null`. When revoking a token, you have two possibilities:

* Setting the expiration time for the token in the past (default);
* Deleting the token from the database whatsoever. To do this, pass `true` as the parameter to the `revokeToken()` method:

```php
// Given that $splitToken contains a valid token
$splitToken = $splitToken->revokeToken(true);
```

#### Clear Expired Tokens

From time to time you will need to delete all expired tokens from the database to reduce the table size and search times. There is a method to do this. It is static, so you have to provide your PDO instance as its parameter. It returns the number of tokens deleted from the database.

```php
$deletedTokens = SplitToken::clearExpiredTokens($dbConnection);
```

#### Notes on Expiration Times

* All expiration times are internally stored as UTC timestamps.
* Expiration times are set, compared and formatted according to the time of the PHP server, so you won't be in trouble even if your database server time is slightly off for some reason.
* Expiration time with value `0` (zero) sets the default value, i.e., the token will expire in an hour.
* If expiration time is set to `null`, the token is eternal and never expires.
* Microseconds for expiration times are ignored for now, their support is planned for a future version.

### Error Handling

SplitToken throws two types of exceptions:

* `InvalidTokenException` is thrown when something really wrong happens to the token itself or to SQL queries related to the token (for example, a token is not found, it has been tampered with, its length is invalid or a PDO statement cannot be executed);
* `SplitTokenException` is thrown in most cases when you do something erroneously (for example, try to store an empty token into the database, try to set a negative user ID etc.).

### Methods

Below all of the SplitToken public methods are outlined.

* `static create(PDO $dbConnection, int|string|null $expirationTime = 0, int|null $userId = null, int|null $tokenType = null, string|null $additionalInfo = null, Oire\Iridium\Key\SharedKey|null $additionalInfoKey = null): self` — Generate a new token. All the parameters are described above, only the database connection is required. Expiration time is by default set to `0` which means the token expires in one hour. If `$additionalInfoKey` is not null, the additional info is encrypted with this key. Throws `SplitTokenException` if trying to set a non-positive user ID.
* `static fromString(string $token, PDO $dbConnection, Oire\Iridium\SharedKey|null $additionalInfoKey): self` — Set and validate a user-provided token. If `$additionalInfoKey` is not null, decrypts the additional info stored in the database with this key.
* `getToken(): string` — Get the token for the current SplitToken instance as a string. Throws `SplitTokenException` if the token was not created or set before.
* `getUserId(): int` — Get the ID of the user the token belongs to, as an integer.
* `getExpirationTime(): int` — Get expiration time for the token as raw timestamp. Returns integer.
* `getExpirationDate(): DateTimeImmutable` — Get expiration time for the token as a DateTimeImmutable object. Returns the date in the current time zone of your PHP server.
* `getExpirationDateFormatted(string $format = 'Y-m-d H:i:s'): string` — Get expiration time for the token as date string. The default format is `2020-11-15 12:34:56`. The `$format` parameter must be a valid [date format](https://www.php.net/manual/en/function.date.php).
* `isEternal(): bool` — check if the token is eternal and never expires. Returns `true` if the token is eternal, `false` if it has expiration time set in the future or already expired.
* `isExpired(): bool` — Check if the token is expired. Returns `true` if the token has already expired, `false` otherwise.
* `getTokenType(): int|null` — Get the type for the current token. Returns integer if the token type was set before, or null if the token has no type.
* `getAdditionalInfo(): string|null` — Get additional info for the token. Returns string or null, if additional info was not set before.
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
```

If PHPCodeSniffer finds any code style errors, fix them in your code.  
When your pull request is submitted, make sure all checks passed on CI.

## License

Copyright © 2021-2025 André Polykanine also known as Menelion Elensúlë, [Oire Software](https://github.com/Oire/).  
This software is licensed under an MIT license.
