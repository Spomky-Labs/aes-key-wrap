<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace AESKW\Tests;

use AESKW\A128KW;
use PHPUnit\Framework\TestCase;

/**
 * This test comes from the JWE specification.
 *
 * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-39#appendix-A.3.3
 */
final class JWETest extends TestCase
{
    /**
     * @test
     */
    public function cEKEncryption()
    {
        // The KEK
        $kek = base64_decode('GawgguFyGrWKav7AX4VKUg', true);

        // The CEK to encrypt (we convert it into a binary string)
        $data = [4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207];
        foreach ($data as $key => $value) {
            $data[$key] = str_pad(dechex($value), 2, '0', STR_PAD_LEFT);
        }
        $data = hex2bin(implode('', $data));

        $wrapped = A128KW::wrap($kek, $data);
        static::assertEquals(base64_decode('6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ', true), $wrapped);
        $unwrapped = A128KW::unwrap($kek, $wrapped);
        static::assertEquals($data, $unwrapped);
    }
}
