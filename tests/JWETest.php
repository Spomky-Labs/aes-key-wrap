<?php

use AESKW\A128KW;

/**
 * This test comes from the JWE specification.
 *
 * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-39#appendix-A.3.3
 */
class JWETest extends \PHPUnit_Framework_TestCase
{
    public function testCEKEncryption()
    {
        // The KEK
        $kek  = base64_decode("GawgguFyGrWKav7AX4VKUg");

        // The CEK to encrypt (we convert it into a binary string)
        $data = [4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207];
        foreach ($data as $key => $value) {
            $data[$key] = str_pad(dechex($value), 2, "0", STR_PAD_LEFT);
        }
        $data = hex2bin(implode("", $data));

        $wrapper = new A128KW();
        $wrapped = $wrapper->wrap($kek, $data);
        $this->assertEquals(base64_decode("6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"), $wrapped);
        $unwrapped = $wrapper->unwrap($kek, $wrapped);
        $this->assertEquals($data, $unwrapped);
    }
}
