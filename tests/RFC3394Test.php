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
use AESKW\A192KW;
use AESKW\A256KW;
use PHPUnit\Framework\TestCase;

/**
 * These tests come from the RFC3394.
 *
 * @see https://www.ietf.org/rfc/rfc3394.txt#4
 */
final class RFC3394Test extends TestCase
{
    /**
     * @test
     */
    public function wrap128BitsKeyDataWith128BitKEK()
    {
        $kek = hex2bin('000102030405060708090A0B0C0D0E0F');
        $data = hex2bin('00112233445566778899AABBCCDDEEFF');

        $wrapped = A128KW::wrap($kek, $data);
        static::assertEquals(hex2bin('1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5'), $wrapped);
        $unwrapped = A128KW::unwrap($kek, $wrapped);
        static::assertEquals($data, $unwrapped);
    }

    /**
     * @test
     */
    public function wrap128BitsKeyDataWith192BitKEK()
    {
        $kek = hex2bin('000102030405060708090A0B0C0D0E0F1011121314151617');
        $data = hex2bin('00112233445566778899AABBCCDDEEFF');

        $wrapped = A192KW::wrap($kek, $data);
        static::assertEquals(hex2bin('96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D'), $wrapped);
        $unwrapped = A192KW::unwrap($kek, $wrapped);
        static::assertEquals($data, $unwrapped);
    }

    /**
     * @test
     */
    public function wrap128BitsKeyDataWith256BitKEK()
    {
        $kek = hex2bin('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F');
        $data = hex2bin('00112233445566778899AABBCCDDEEFF');

        $wrapped = A256KW::wrap($kek, $data);
        static::assertEquals(hex2bin('64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7'), $wrapped);
        $unwrapped = A256KW::unwrap($kek, $wrapped);
        static::assertEquals($data, $unwrapped);
    }

    /**
     * @test
     */
    public function wrap192BitsKeyDataWith192BitKEK()
    {
        $kek = hex2bin('000102030405060708090A0B0C0D0E0F1011121314151617');
        $data = hex2bin('00112233445566778899AABBCCDDEEFF0001020304050607');

        $wrapped = A192KW::wrap($kek, $data);
        static::assertEquals(hex2bin('031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2'), $wrapped);
        $unwrapped = A192KW::unwrap($kek, $wrapped);
        static::assertEquals($data, $unwrapped);
    }

    /**
     * @test
     */
    public function wrap192BitsKeyDataWith256BitKEK()
    {
        $kek = hex2bin('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F');
        $data = hex2bin('00112233445566778899AABBCCDDEEFF0001020304050607');

        $wrapped = A256KW::wrap($kek, $data);
        static::assertEquals(hex2bin('A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1'), $wrapped);
        $unwrapped = A256KW::unwrap($kek, $wrapped);
        static::assertEquals($data, $unwrapped);
    }

    /**
     * @test
     */
    public function wrap256BitsKeyDataWith256BitKEK()
    {
        $kek = hex2bin('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F');
        $data = hex2bin('00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F');

        $wrapped = A256KW::wrap($kek, $data);
        static::assertEquals(hex2bin('28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21'), $wrapped);
        $unwrapped = A256KW::unwrap($kek, $wrapped);
        static::assertEquals($data, $unwrapped);
    }
}
