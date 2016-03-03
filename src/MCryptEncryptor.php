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

final class MCryptEncryptor implements EncryptorInterface
{
    private $kek;

    public function __construct($kek)
    {
        $this->kek = $kek;
    }

    /**
     * {@inheritdoc}
     */
    public function encrypt($data)
    {
        return mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $this->kek, $data, MCRYPT_MODE_ECB);
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt($data)
    {
        return mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $this->kek, $data, MCRYPT_MODE_ECB);
    }
}
