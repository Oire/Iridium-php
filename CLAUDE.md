# CLAUDE.md - Iridium PHP

## Project Overview

Iridium is a security library for PHP providing authenticated encryption, password hashing, split token authentication, and URL-safe Base64 encoding. It is a mature, production library (v2.0) with zero runtime dependencies. Package name: `oire/iridium`.

## Quick Reference

```bash
# Install dependencies
composer install

# Run tests
./vendor/bin/phpunit

# Static analysis (strictest level)
./vendor/bin/psalm

# Code style check
./vendor/bin/php-cs-fixer fix --diff --dry-run

# Code style fix
./vendor/bin/php-cs-fixer fix
```

Always run all three checks before committing.

## Project Structure

```
src/
  Base64.php          # URL-safe Base64 encoding/decoding
  Crypt.php           # AES-256-CTR + HMAC-SHA384 authenticated encryption
  Password.php        # Password hashing (Argon2id/Bcrypt wrapper)
  SplitToken.php      # Split token pattern for secure token auth
  Exception/          # Exception hierarchy (all extend IridiumException)
  Key/
    SharedKey.php     # 32-byte shared encryption key wrapper
    DerivedKeys.php   # Derived encryption + authentication keys via HKDF
tests/
  *Test.php           # One test class per source module
```

## Coding Conventions

- **PHP 8.3+** required. Extensions: PDO, Mbstring, OpenSSL.
- **`declare(strict_types=1);`** in every PHP file.
- **All classes are `final`** except base exception classes.
- **Namespace**: `Oire\Iridium\` (PSR-4 mapped to `src/`). Tests: `Oire\Iridium\Tests\`.
- **Readonly constructor promotion** for value objects.
- **Static factory methods** for object creation (e.g., `SharedKey::create()`, `SplitToken::fromString()`).
- **Static factory methods on exceptions** for descriptive construction (e.g., `InvalidTokenException::sqlError()`).
- Code style is enforced by `php-cs-fixer` using rules from the `oire/php-code-style` package.

## Formatting Rules

- LF line endings, UTF-8.
- 4-space indentation for PHP and XML; 2-space for YAML.
- Final newline on all files except Markdown.
- Trim trailing whitespace except in Markdown.

## Testing

- PHPUnit with test suite named "Colloportus" (see `phpunit.xml.dist`).
- Tests use SQLite in-memory databases for `SplitToken` persistence tests.
- CI runs on PHP 8.3 and 8.4, both Ubuntu and Windows.

## Static Analysis

- Psalm at **error level 1** (strictest) with `strictBinaryOperands`, `findUnusedCode`, and `findUnusedVariablesAndParams` enabled.
- Psalm PHPUnit plugin is active.
- Use `@psalm-suppress` inline annotations sparingly and only when justified (e.g., suppressing false-positive unused code on exception factory methods).

## CI Pipelines (GitHub Actions)

1. **run-tests.yml** - PHPUnit on PHP 8.3/8.4, Ubuntu + Windows.
2. **psalm.yml** - Static analysis on PHP 8.3/8.4.
3. **php-cs-fixer.yml** - Code style check (dry-run) on PHP 8.3.

## Security Considerations

This is a cryptographic library. When making changes:

- Never weaken cryptographic parameters (key sizes, hash functions, algorithms).
- Preserve constant-time comparisons (`hash_equals()`). Never replace with `===`.
- Maintain the encrypt-then-MAC pattern in `Crypt`.
- Keep the split token pattern intact: selector (plaintext lookup) + verifier (hashed comparison).
- Do not introduce timing side channels.
