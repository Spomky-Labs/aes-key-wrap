# Threat model

This file steers the [OSS Scanner](https://github.com/anthropics/oss-scanner). Vulnerabilities found by other means
are reported as described in [SECURITY.md](../SECURITY.md).

## What this project does

`spomky-labs/aes-key-wrap` is a small PHP library (namespace `AESKW\`) that implements the AES Key Wrap algorithm of
RFC 3394 and the AES Key Wrap with Padding algorithm of RFC 5649. It provides three final classes, one per AES key
size: `A128KW`, `A192KW` and `A256KW` (`src/A128KW.php`, `src/A192KW.php`, `src/A256KW.php`). They implement the
`Wrapper` interface (`src/Wrapper.php`) through the `AESKW` trait (`src/AESKW.php`), which holds the whole algorithm
in two static methods:

- `wrap(string $kek, string $key, bool $padding_enabled = false)` wraps a key under a key-encryption key (KEK);
- `unwrap(string $kek, string $key, bool $padding_enabled = false)` unwraps a wrapped key and checks its integrity.

With `$padding_enabled` false, the key is a sequence of 64-bit blocks and the initial value is the default one of
RFC 3394 section 2.2.3.1, `A6A6A6A6A6A6A6A6`. With `$padding_enabled` true, the key has any length of at least one
byte, it is padded with zero bytes to a multiple of 8 bytes, and the initial value is the alternative initial value
of RFC 5649 section 3: `A65959A6` followed by the 32-bit message length indicator (MLI). AES is computed by ext-openssl
(`openssl_encrypt()` and `openssl_decrypt()` in ECB mode on single 128-bit blocks, without padding), and the byte
strings are handled with ext-mbstring in `8bit` mode. The library does no I/O and keeps no state.

Its consumers include `web-auth/cose-lib` and `web-token/jwt-library`, which build the COSE and JOSE algorithms
A128KW, A192KW and A256KW on it, and the ECDH and PBES2 variants that wrap a key with them. In those protocols the
wrapped key is the encrypted content-encryption key of a message received from the network, and they use the RFC 3394
mode (`$padding_enabled` false).

## Where untrusted input enters

The attacker is the sender of the wrapped key that the application hands to `unwrap()`: in JOSE and COSE, the sender
of a message, who chooses the encrypted key of a recipient. The attacker does not know the KEK. Untrusted:

- The `$key` argument of `unwrap()`, the wrapped key: its length and every byte of it, and therefore the initial
  value, the MLI and the padding bytes it decrypts to.

What is trusted:

- The KEK and the class it is used with: the application chooses `A128KW`, `A192KW` or `A256KW` and passes a KEK of
  16, 24 or 32 bytes respectively. When the KEK is derived from a key agreement or a password (the ECDH and PBES2
  algorithms of JOSE and COSE), the derivation is done by the caller: this library only receives the result.
- The key given to `wrap()`, and the `$padding_enabled` argument of both methods. They come from the application.
- PHP, ext-openssl and ext-mbstring.

## Security properties that must hold

- `unwrap()` returns a key only if the integrity check of the RFCs passes on the initial value it recovers: it is
  `A6A6A6A6A6A6A6A6`, or, with `$padding_enabled` true, it is `A65959A6` followed by an MLI with
  8 * (n - 1) < MLI <= 8 * n for the n recovered 64-bit blocks, and every padding byte after the first MLI bytes is
  zero. Otherwise it throws, and returns no part of the decrypted data.
- `unwrap($kek, wrap($kek, $key, $p), $p)` returns `$key` for every key `wrap()` accepts, and `wrap()` produces the
  test vectors of RFC 3394 section 4 and RFC 5649 section 6.
- Every failure of `wrap()` and `unwrap()` is an `InvalidArgumentException`. Malformed input never escapes as a PHP
  warning, notice, `TypeError` or `Error`.
- The message of a failed `unwrap()` depends only on the length of the wrapped key: `Bad data` for 8 bytes or less,
  `Unable to decrypt the data` for a longer one whose length is not a multiple of 8 bytes, and
  `Integrity check failed!` for every other wrapped key that fails the initial value, MLI or padding check. Failed
  unwraps cannot be told apart in a way that depends on the decrypted value.
- No exception message or PHP diagnostic carries the KEK, the key or any decrypted data.
- The cost of `wrap()` and `unwrap()` is linear in the length of their input: six AES block operations per 64-bit
  block, as the RFCs define them.

## Components that matter most

- `AESKW::unwrap()`: the unwrapping process of RFC 3394 section 2.2.2, and the single AES decryption of RFC 5649
  section 4.2 for a wrapped key of two 64-bit blocks.
- `AESKW::checkInitialValue()`: the integrity check of RFC 3394 section 2.2.3 and the MLI and padding checks of
  RFC 5649 section 3.
- `AESKW::wrap()`, `getInitialValue()` and `checkKeySize()`: the wrapping process and the padding of RFC 5649.
- The helpers of the trait: `toXBits()` (the encoding of the counter t and of the MLI), `getMSB()` and `getLSB()`
  (the split of a 128-bit block), `encrypt()` and `decrypt()` (the calls to ext-openssl), and the `getMethod()` of
  each class, which selects the AES key size.

## How to exercise it

The image has PHP 8.4 with the openssl and mbstring extensions, the dependencies of `composer.json` in `vendor/`
(PHPUnit 9 among them), and the QA tools of the phpqa image on the `PATH`. `composer.json` allows PHP 8.0 and later.
Run the tests with the PHPUnit 9 of `vendor/`, from `/src`:

    vendor/bin/phpunit
    vendor/bin/phpunit --filter ExceptionTest

`phpunit.xml.dist` and the `@test` annotations are written for PHPUnit 9; the `phpunit-11` of the image runs them
but reports them as deprecated. `thecodingmachine/safe` 1.x, installed for `infection/infection` 0.25, prints PHP 8.4
deprecation notices ("Implicitly marking parameter ... as nullable") whenever `vendor/autoload.php` is loaded. They
come from that dev tool, not from this library, and do not change the result. The configuration turns PHP warnings
and notices raised during a test into test errors.

- The tests are in `tests/`: `RFC3394Test.php` and `RFC5649Test.php` replay the test vectors of both RFCs,
  `One64BitBlockTest.php` the wrap of a single 64-bit block, `JWETest.php` the A128KW example of the JWE
  specification, and `ExceptionTest.php` the inputs that must be rejected.
- A reproducer goes into `ExceptionTest.php` or a new file in `tests/` (namespace `AESKW\Tests`) whose name ends with
  `Test.php`, as only those files are run.
- `tests/Performance.php` is a benchmark, not a test, and PHPUnit does not run it.

## How we rate severity

No advisory has been published for this library, so this scale is not calibrated on past reports. It follows the
threat models of the projects that depend on it, `web-auth/cose-lib` first.

- Critical: in the RFC 3394 mode (`$padding_enabled` false, the one JOSE and COSE use), `unwrap()` accepting a
  wrapped key that was not produced under the KEK with a probability well above the 2^-64 the integrity check
  allows, or the recovery of the KEK, or of the key inside a wrapped key, through `unwrap()` without the KEK;
  executing code or reading files through the processing of a wrapped key.
- High: the same in the RFC 5649 mode (`$padding_enabled` true); an unwrap oracle, that is failed unwraps that a
  sender can tell apart by the exception, its message or a remotely measurable time difference depending on the
  decrypted value, when this helps to recover or forge a wrapped key; a `wrap()` whose output reveals the key it
  wraps.
- Medium: a single call whose time or memory grows faster than the length of its input; the KEK, a key or decrypted
  data written into an exception message or a PHP diagnostic; a time difference depending on the KEK or the decrypted
  value that can be measured remotely but has not been shown to help recover or forge a key.
- Low: malformed input that escapes as a PHP warning, notice, `TypeError` or `Error` instead of an
  `InvalidArgumentException`; a deviation from the RFCs with no effect on integrity or confidentiality (an
  interoperability bug); a time difference that needs local access; disclosure of non-sensitive internals.

## Anything to leave alone

- Bugs in PHP, OpenSSL and mbstring: they are separate projects. A misuse of them by this library is in scope.
- The dev tools of `composer.json` (PHPUnit, PHPStan, ECS, Rector, Infection) and what they print.
- Reports that need the attacker to choose the KEK, the key given to `wrap()` or the mode: they are trusted.
- The documented behaviours beyond RFC 3394: the RFC 3394 mode accepts "one or more 64-bit blocks" (docblock of
  `Wrapper::wrap()`) and wraps a single block with one AES operation (`tests/One64BitBlockTest.php`), and `unwrap()`
  with `$padding_enabled` true also accepts the RFC 3394 initial value, as the docblock of `Wrapper::unwrap()` states.
- The cost that the RFCs define: `wrap()` and `unwrap()` perform six AES block operations per 64-bit block. A report
  about a large input is in scope only when the cost grows faster than its length.
- `tests/`, `doc/`, `.github/`, `Makefile` and the configuration of the QA tools (`ecs.php`, `rector.php`,
  `phpstan.neon`, `infection.json`, `.php_cs.dist`).

## Reports

Include a reproducer written as a PHPUnit test in `tests/`, the mode (`$padding_enabled`) and the KEK size it needs,
and a patch against the scanned branch. Fixes are released as 7.x versions.
