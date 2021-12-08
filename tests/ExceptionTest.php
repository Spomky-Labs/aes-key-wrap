<?php

declare(strict_types=1);

namespace AESKW\Tests;

use AESKW\A128KW;
use AESKW\A192KW;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

/**
 * These tests come from the RFC3394.
 *
 * @see https://www.ietf.org/rfc/rfc3394.txt#4
 *
 * @internal
 */
final class ExceptionTest extends TestCase
{
    /**
     * @test
     */
    public function integrityCheckFailed(): void
    {
        $this->expectExceptionMessage('Integrity check failed');
        $this->expectException(InvalidArgumentException::class);
        $kek = hex2bin('000102030405060708090A0B0C0D0E0F');
        $data = hex2bin('1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE4');

        A128KW::unwrap($kek, $data);
    }

    /**
     * @test
     */
    public function a128KWBadKeySize(): void
    {
        $this->expectExceptionMessage('Bad key size');
        $this->expectException(InvalidArgumentException::class);
        $kek = hex2bin('00010203040506070809101112131415');
        $data = hex2bin('0011223344');

        A128KW::wrap($kek, $data);
    }

    /**
     * @test
     */
    public function a128KWEmptyKey(): void
    {
        $this->expectExceptionMessage('Bad key size');
        $this->expectException(InvalidArgumentException::class);
        $kek = hex2bin('00010203040506070809101112131415');
        $data = hex2bin('');

        A128KW::wrap($kek, $data, true);
    }

    /**
     * @test
     */
    public function a128KWIntegrityNotVerified(): void
    {
        $this->expectExceptionMessage('Integrity check failed');
        $this->expectException(InvalidArgumentException::class);
        $kek = hex2bin('5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8');
        $data = hex2bin('138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6b');

        A192KW::unwrap($kek, $data, true);
    }

    /**
     * @test
     */
    public function wrap64BitsKeyDataWith128BitKEK(): void
    {
        $this->expectExceptionMessage('Bad data');
        $this->expectException(InvalidArgumentException::class);
        $kek = hex2bin('000102030405060708090A0B0C0D0E0F');
        $data = hex2bin('F4740052E82A2251');

        A128KW::unwrap($kek, $data);
    }

    /**
     * @test
     */
    public function badData(): void
    {
        $this->expectExceptionMessage('Integrity check failed');
        $this->expectException(InvalidArgumentException::class);
        $kek = hex2bin('000102030405060708090A0B0C0D0E0F');
        $data = hex2bin('F4740052E82A225174CE86FBD7B805E6');

        A128KW::unwrap($kek, $data);
    }
}
