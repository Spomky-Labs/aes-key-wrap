<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace AESKW;

final class OpenSSLEncryptor implements EncryptorInterface
{
    private $kek;
    private $method;

    public function __construct($kek)
    {
        $this->kek = $kek;
        $this->method = 'aes-'.(mb_strlen($kek, '8bit') * 8).'-ecb';
    }

    /**
     * {@inheritdoc}
     */
    public function encrypt($data)
    {
        return openssl_encrypt($data, $this->method, $this->kek, OPENSSL_ZERO_PADDING | OPENSSL_RAW_DATA);
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt($data)
    {
        return openssl_decrypt($data, $this->method, $this->kek, OPENSSL_ZERO_PADDING | OPENSSL_RAW_DATA);
    }
}
