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

/**
 * This class is used to check the performance of the library on the current platform.
 * You just have to call Performance::run();
 * By default, tests are performed 1000 times.
 * You can modify it by passing a positive integer  as first argument:
 * Performance::run(10000);.
 */
final class Performance
{
    public static function run(int $nb = 1000)
    {
        if (1 > $nb) {
            throw new \InvalidArgumentException('You must perform at least 1 test.');
        }
        $cases = self::getData();
        foreach ($cases as $case) {
            self::wrap($nb, $case);
            self::unwrap($nb, $case);
        }
    }

    private static function wrap(int $nb, array $case)
    {
        $class = $case['class'];
        $kek = $case['kek'];
        $data = $case['data'];
        $padding = $case['padding'];
        $time = self::do($class, 'wrap', $nb, $kek, $data, $padding);

        printf('%s: %f milliseconds/wrap'.PHP_EOL, $case['name'], $time);
    }

    private static function unwrap(int $nb, array $case)
    {
        $class = $case['class'];
        $kek = $case['kek'];
        $result = $case['result'];
        $padding = $case['padding'];
        $time = self::do($class, 'unwrap', $nb, $kek, $result, $padding);

        printf('%s: %f milliseconds/unwrap'.PHP_EOL, $case['name'], $time);
    }

    /**
     * @param array ...$args
     */
    private static function do(string $class, string $method, int $nb, ...$args): float
    {
        $time_start = microtime(true);
        for ($i = 0; $i < $nb; ++$i) {
            \call_user_func_array([$class, $method], $args);
        }
        $time_end = microtime(true);

        return ($time_end - $time_start) / $nb * 1000;
    }

    private static function getData(): array
    {
        return [
            [
                'class' => A128KW::class,
                'name' => 'RFC3394: 128 bits data with 128 bits KEK',
                'kek' => hex2bin('000102030405060708090A0B0C0D0E0F'),
                'data' => hex2bin('00112233445566778899AABBCCDDEEFF'),
                'result' => hex2bin('1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5'),
                'padding' => false,
            ],
            [
                'class' => A192KW::class,
                'name' => 'RFC3394: 128 bits data with 192 bits KEK',
                'kek' => hex2bin('000102030405060708090A0B0C0D0E0F1011121314151617'),
                'data' => hex2bin('00112233445566778899AABBCCDDEEFF'),
                'result' => hex2bin('96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D'),
                'padding' => false,
            ],
            [
                'class' => A256KW::class,
                'name' => 'RFC3394: 128 bits data with 256 bits KEK',
                'kek' => hex2bin('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F'),
                'data' => hex2bin('00112233445566778899AABBCCDDEEFF'),
                'result' => hex2bin('64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7'),
                'padding' => false,
            ],
            [
                'class' => A192KW::class,
                'name' => 'RFC3394: 192 bits data with 192 bits KEK',
                'kek' => hex2bin('000102030405060708090A0B0C0D0E0F1011121314151617'),
                'data' => hex2bin('00112233445566778899AABBCCDDEEFF0001020304050607'),
                'result' => hex2bin('031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2'),
                'padding' => false,
            ],
            [
                'class' => A256KW::class,
                'name' => 'RFC3394: 192 bits data with 256 bits KEK',
                'kek' => hex2bin('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F'),
                'data' => hex2bin('00112233445566778899AABBCCDDEEFF0001020304050607'),
                'result' => hex2bin('A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1'),
                'padding' => false,
            ],
            [
                'class' => A256KW::class,
                'name' => 'RFC3394: 256 bits data with 256 bits KEK',
                'kek' => hex2bin('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F'),
                'data' => hex2bin('00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F'),
                'result' => hex2bin('28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21'),
                'padding' => false,
            ],
            [
                'class' => A192KW::class,
                'name' => 'RFC5649 160 bits data with 192 bits KEK',
                'kek' => hex2bin('5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8'),
                'data' => hex2bin('c37b7e6492584340bed12207808941155068f738'),
                'result' => hex2bin('138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a'),
                'padding' => true,
            ],
            [
                'class' => A192KW::class,
                'name' => 'RFC5649 56 bits data with 192 bits KEK',
                'kek' => hex2bin('5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8'),
                'data' => hex2bin('466f7250617369'),
                'result' => hex2bin('afbeb0f07dfbf5419200f2ccb50bb24f'),
                'padding' => true,
            ],
        ];
    }
}
