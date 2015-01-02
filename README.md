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


This library provides an implementation of the [RFC 3394](https://tools.ietf.org/html/rfc3394).

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
            "spomky-labs/aes-key-wrap": "dev-master"
        }
    }

## Licence

This software is release under MIT licence.
