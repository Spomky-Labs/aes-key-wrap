<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use AESKW\A128KW;
use AESKW\A192KW;
use AESKW\A256KW;

/**
 * These tests come from the RFC3394.
 *
 * @see https://www.ietf.org/rfc/rfc3394.txt#4
 */
class ExceptionTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @expectedException        InvalidArgumentException
     * @expectedExceptionMessage Bad KEK size
     */
    public function testAESKWBadKEKSize()
    {
        $kek = hex2bin('00');
        $data = hex2bin('00112233445566778899AABBCCDDEEFF');

        A128KW::wrap($kek, $data);
    }

    /**
     * @expectedException        InvalidArgumentException
     * @expectedExceptionMessage Bad KEK size
     */
    public function testA128KWBadKEKSize()
    {
        $kek = hex2bin('0001020304050607');
        $data = hex2bin('00112233445566778899AABBCCDDEEFF');

        A128KW::wrap($kek, $data);
    }

    /**
     * @expectedException        InvalidArgumentException
     * @expectedExceptionMessage Bad KEK size
     */
    public function testA192KWBadKEKSize()
    {
        $kek = hex2bin('00010203040506070809101112131415');
        $data = hex2bin('00112233445566778899AABBCCDDEEFF');

        A192KW::wrap($kek, $data);
    }

    /**
     * @expectedException        InvalidArgumentException
     * @expectedExceptionMessage Bad KEK size
     */
    public function testA256KWBadKEKSize()
    {
        $kek = hex2bin('00010203040506070809101112131415');
        $data = hex2bin('00112233445566778899AABBCCDDEEFF');

        A256KW::wrap($kek, $data);
    }

    /**
     * @expectedException        RuntimeException
     * @expectedExceptionMessage Integrity check failed
     */
    public function testIntegrityCheckFailed()
    {
        $kek = hex2bin('000102030405060708090A0B0C0D0E0F');
        $data = hex2bin('1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE4');

        A128KW::unwrap($kek, $data);
    }

    /**
     * @expectedException        InvalidArgumentException
     * @expectedExceptionMessage Bad key size
     */
    public function testA128KWBadKeySize()
    {
        $kek = hex2bin('00010203040506070809101112131415');
        $data = hex2bin('0011223344');

        A128KW::wrap($kek, $data);
    }

    /**
     * @expectedException        InvalidArgumentException
     * @expectedExceptionMessage Bad key size
     */
    public function testA128KWEmptyKey()
    {
        $kek = hex2bin('00010203040506070809101112131415');
        $data = hex2bin('');

        A128KW::wrap($kek, $data, true);
    }

    /**
     * @expectedException        RuntimeException
     * @expectedExceptionMessage Integrity check failed
     */
    public function testA128KWIntegrityNotVerified()
    {
        $kek = hex2bin('5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8');
        $data = hex2bin('138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6b');

        A192KW::unwrap($kek, $data, true);
    }

    /**
     * @expectedException        RuntimeException
     * @expectedExceptionMessage Bad data
     */
    public function testWrap64BitsKeyDataWith128BitKEK()
    {
        $kek = hex2bin('000102030405060708090A0B0C0D0E0F');
        $data = hex2bin('F4740052E82A2251');

        A128KW::unwrap($kek, $data);
    }

    /**
     * @expectedException        RuntimeException
     * @expectedExceptionMessage Integrity check failed
     */
    public function testBadData()
    {
        $kek = hex2bin('000102030405060708090A0B0C0D0E0F');
        $data = hex2bin('F4740052E82A225174CE86FBD7B805E6');

        A128KW::unwrap($kek, $data);
    }
}
