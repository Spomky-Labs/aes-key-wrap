<?php

declare(strict_types=1);

namespace AESKW\Tests;

use AESKW\A128KW;
use PHPUnit\Framework\TestCase;
use const STR_PAD_LEFT;

/**
 * This test comes from the JWE specification.
 *
 * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-39#appendix-A.3.3
 *
 * @internal
 */
final class JWETest extends TestCase
{
    /**
     * @test
     */
    public function cEKEncryption(): void
    {
        // The KEK
        $kek = base64_decode('GawgguFyGrWKav7AX4VKUg', true);

        // The CEK to encrypt (we convert it into a binary string)
        $data = [
            4,
            211,
            31,
            197,
            84,
            157,
            252,
            254,
            11,
            100,
            157,
            250,
            63,
            170,
            106,
            206,
            107,
            124,
            212,
            45,
            111,
            107,
            9,
            219,
            200,
            177,
            0,
            240,
            143,
            156,
            44,
            207,
        ];
        foreach ($data as $key => $value) {
            $data[$key] = str_pad(dechex($value), 2, '0', STR_PAD_LEFT);
        }
        $data = hex2bin(implode('', $data));

        $wrapped = A128KW::wrap($kek, $data);
        static::assertSame(base64_decode('6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ', true), $wrapped);
        $unwrapped = A128KW::unwrap($kek, $wrapped);
        static::assertSame($data, $unwrapped);
    }
}
