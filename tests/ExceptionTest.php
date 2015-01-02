<?php

use AESKW\A128KW;
use AESKW\A192KW;
use AESKW\A256KW;

/**
 * These tests come from the RFC3394
 * @see https://www.ietf.org/rfc/rfc3394.txt#4
 */
class ExceptionTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @expectedException        InvalidArgumentException
     * @expectedExceptionMessage Bad key size
     */
    public function testAESKWBadKeySize()
    {
        $kek  = hex2bin("00");
        $data = hex2bin("00112233445566778899AABBCCDDEEFF");

        $wrapper = new A128KW();

        $wrapper->wrap($kek, $data);
    }

    /**
     * @expectedException        InvalidArgumentException
     * @expectedExceptionMessage Bad key size
     */
    public function testA128KWBadKeySize()
    {
        $kek  = hex2bin("0001020304050607");
        $data = hex2bin("00112233445566778899AABBCCDDEEFF");

        $wrapper = new A128KW();

        $wrapper->wrap($kek, $data);
    }

    /**
     * @expectedException        InvalidArgumentException
     * @expectedExceptionMessage Bad key size
     */
    public function testA192KWBadKeySize()
    {
        $kek  = hex2bin("00010203040506070809101112131415");
        $data = hex2bin("00112233445566778899AABBCCDDEEFF");

        $wrapper = new A192KW();

        $wrapper->wrap($kek, $data);
    }

    /**
     * @expectedException        InvalidArgumentException
     * @expectedExceptionMessage Bad key size
     */
    public function testA256KWBadKeySize()
    {
        $kek  = hex2bin("00010203040506070809101112131415");
        $data = hex2bin("00112233445566778899AABBCCDDEEFF");

        $wrapper = new A256KW();

        $wrapper->wrap($kek, $data);
    }

    /**
     * @expectedException        RuntimeException
     * @expectedExceptionMessage Integrity check failed
     */
    public function testIntegrityCheckFailed()
    {
        $kek  = hex2bin("000102030405060708090A0B0C0D0E0F");
        $data = hex2bin("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE4");

        $wrapper = new A128KW();

        $wrapper->unwrap($kek, $data);
    }

    /**
     * @expectedException        InvalidArgumentException
     * @expectedExceptionMessage Bad data
     */
    public function testWrap64BitsKeyDataWith128BitKEK()
    {
        $kek  = hex2bin("000102030405060708090A0B0C0D0E0F");
        $data = hex2bin("F4740052E82A2251");

        $wrapper = new A128KW();

        $wrapper->unwrap($kek, $data);
    }

    /**
     * @expectedException        RuntimeException
     * @expectedExceptionMessage Integrity check failed
     */
    public function testBadData()
    {
        $kek  = hex2bin("000102030405060708090A0B0C0D0E0F");
        $data = hex2bin("F4740052E82A225174CE86FBD7B805E6");

        $wrapper = new A128KW();

        $wrapper->unwrap($kek, $data);
    }
}
