# PHP AES Key Wrap

[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/Spomky-Labs/aes-key-wrap/badges/quality-score.png?s=fe3d53cad6f5f4bb08937b8fd3a130724f870a42)](https://scrutinizer-ci.com/g/Spomky-Labs/aes-key-wrap/)
[![Code Coverage](https://scrutinizer-ci.com/g/Spomky-Labs/aes-key-wrap/badges/coverage.png?s=e7e3e9b9cbcdf8fa798c3b326fea459e1ad90bc0)](https://scrutinizer-ci.com/g/Spomky-Labs/aes-key-wrap/)

[![Build Status](https://travis-ci.org/Spomky-Labs/aes-key-wrap.svg?branch=master)](https://travis-ci.org/Spomky-Labs/aes-key-wrap)
[![HHVM Status](http://hhvm.h4cc.de/badge/spomky-labs/aes-key-wrap.png)](http://hhvm.h4cc.de/package/spomky-labs/aes-key-wrap)

[![SensioLabsInsight](https://insight.sensiolabs.com/projects/e61c91cf-1860-4416-946b-4c7b74ea01a5/big.png)](https://insight.sensiolabs.com/projects/e61c91cf-1860-4416-946b-4c7b74ea01a5)

[![Latest Stable Version](https://poser.pugx.org/spomky-labs/aes-key-wrap/v/stable.png)](https://packagist.org/packages/spomky-labs/aes-key-wrap)
[![Latest Unstable Version](https://poser.pugx.org/spomky-labs/aes-key-wrap/v/unstable.png)](https://packagist.org/packages/spomky-labs/aes-key-wrap)
[![Total Downloads](https://poser.pugx.org/spomky-labs/aes-key-wrap/downloads.png)](https://packagist.org/packages/spomky-labs/aes-key-wrap)
[![License](https://poser.pugx.org/spomky-labs/aes-key-wrap/license.png)](https://packagist.org/packages/spomky-labs/aes-key-wrap)


This library provides an implementation of the [RFC 3394 (Advanced Encryption Standard (AES) Key Wrap Algorithm)](https://tools.ietf.org/html/rfc3394) and the [RFC 5649 (Advanced Encryption Standard (AES) Key Wrap with Padding Algorithm)](https://tools.ietf.org/html/rfc5649).

## The Release Process ##

We manage the releases of the library through features and time-based models.

- A new patch version comes out every month when you made backwards-compatible bug fixes.
- A new minor version comes every six months when we added functionality in a backwards-compatible manner.
- A new major version comes every year when we make incompatible API changes.

The meaning of "patch" "minor" and "major" comes from the Semantic [Versioning strategy](http://semver.org/).

This release process applies for all versions.

### Backwards Compatibility

We allow developers to upgrade with confidence from one minor version to the next one.

Whenever keeping backward compatibility is not possible, the feature, the enhancement or the bug fix will be scheduled for the next major version.

## Prerequisites ##

This library needs at least `PHP 5.4`

## Installation ##

The preferred way to install this library is to rely on Composer:

    {
        "require": {
            // ...
            "spomky-labs/aes-key-wrap": "~1.0.0"
        }
    }

## How to use ##

### Wrap a key using RFC3394 ###

In the following example, we will wrap the key `key` using the KEK `kek` using `AES 128`:

	// We use the AES 128 algorithm
	use AESKW\A128KW;

	// The Key Encryption Key
    $kek  = hex2bin("000102030405060708090A0B0C0D0E0F");

    // The key we want to wrap
    $key  = hex2bin("00112233445566778899AABBCCDDEEFF");

    // We create an instance of the wrapper
    $wrapper = new A128KW();

    // We wrap the key
    $wrapped_key = $wrapper->wrap($kek, $key); // Must return "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"

    // We unwrap the key
    $unwrapped_key = $wrapper->unwrap($kek, $wrapped_key); // The result must be the same value as the key

### Wrap a key using RFC5649 ###

In the following example, we will wrap the key `key` using the KEK `kek` using `AES 128`. The main difference with the RFC3394 is that you can wrap a key of any practical size:

	// We use the AES 128 algorithm
	use AESKW\A128KW;

	// The Key Encryption Key
    $kek  = hex2bin("000102030405060708090A0B0C0D0E0F");

    // The key we want to wrap. Please note that the size is not exactly a 64 bits-block
    $key  = hex2bin("0011223344");

    // We create an instance of the wrapper
    $wrapper = new A128KW();

    // We wrap the key. Please not that the third parameter enable the key padding (RFC6549)
    $wrapped_key = $wrapper->wrap($kek, $key, true); // Must return "9E53E571ED4669A51A4B8724788F8C80"

    // We unwrap the key. Please not that the third parameter enable the key padding (RFC6549)
    $unwrapped_key = $wrapper->unwrap($kek, $wrapped_key, true); // The result must be the same value as the key

## Licence ##

This software is release under MIT licence.
