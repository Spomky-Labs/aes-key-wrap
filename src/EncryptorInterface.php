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

interface EncryptorInterface
{
    /**
     * @param string $data
     *
     * @return string
     */
    public function encrypt($data);

    /**
     * @param string $data
     *
     * @return string
     */
    public function decrypt($data);
}
