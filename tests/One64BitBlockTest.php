<?php

use AESKW\A128KW;
use AESKW\A192KW;
use AESKW\A256KW;

/**
 * These tests come from the RFC3394
 * @see https://www.ietf.org/rfc/rfc3394.txt#4
 */
class One64BitBlockTest extends \PHPUnit_Framework_TestCase
{
    public function testWrap64BitsKeyDataWith128BitKEK()
    {
        $kek  = hex2bin("000102030405060708090A0B0C0D0E0F");
        $data = hex2bin("0011223344556677");

        $wrapper = new A128KW();

        $wrapped = $wrapper->wrap($kek, $data);
        $this->assertEquals(hex2bin("F4740052E82A225174CE86FBD7B805E7"), $wrapped);
        $unwrapped = $wrapper->unwrap($kek, $wrapped);
        $this->assertEquals($data, $unwrapped);
    }

    public function testWrap64BitsKeyDataWith192BitKEK()
    {
        $kek  = hex2bin("000102030405060708090A0B0C0D0E0F1011121314151617");
        $data = hex2bin("0011223344556677");

        $wrapper = new A192KW();

        $wrapped = $wrapper->wrap($kek, $data);
        $this->assertEquals(hex2bin("DFE8FD5D1A3786A7351D385096CCFB29"), $wrapped);
        $unwrapped = $wrapper->unwrap($kek, $wrapped);
        $this->assertEquals($data, $unwrapped);
    }

    public function testWrap64BitsKeyDataWith256BitKEK()
    {
        $kek  = hex2bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        $data = hex2bin("0011223344556677");

        $wrapper = new A256KW();

        $wrapped = $wrapper->wrap($kek, $data);
        $this->assertEquals(hex2bin("794314D454E3FDE1F661BD9F31FBFA31"), $wrapped);
        $unwrapped = $wrapper->unwrap($kek, $wrapped);
        $this->assertEquals($data, $unwrapped);
    }
}
