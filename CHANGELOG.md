# Version 1.2

* [#52](https://github.com/Oire/Iridium-php/pull/52):
  Add release notes config; Add PHP CodeSniffer to Github Actions CI.
* [#53](https://github.com/Oire/Iridium-php/pull/53):
  Deprecate SymmetricKey in favor of SharedKey for simpler naming.
* [#75](https://github.com/Oire/Iridium-php/pull/75):
  Deprecate Osst in favor of SplitToken for simpler naming.

# Version 1.1

* [#19](https://github.com/Oire/Iridium-php/pull/19):
  Add eternal tokens, i.e., tokens that never expire until revoked manually.
* [#17](https://github.com/Oire/Iridium-php/pull/17):
  Regular dependencies upgrade.
* [#20](https://github.com/Oire/Iridium-php/pull/20):
  Add support for [Captain Hook](https://github.com/captainhookphp/captainhook), a git hook solution for PHP projects.
* [#27](https://github.com/Oire/Iridium-php/pull/27):
  Wrap the internal derived keys into a value object.
* Drop support for PHP 7.3, the minimum version is 7.4.
* [#43](https://github.com/Oire/Iridium-php/pull/43):
  Add basic PHP CodeSniffer ruleset.
  Add typed properties.
* The `tokenIsExpired()` method is deprecated and will be removed in version 2.0, use `isExpired()` instead.
