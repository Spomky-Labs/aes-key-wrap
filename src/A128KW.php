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

final class A128KW
{
    use AESKW;

    /**
     * {@inheritdoc}
     */
    protected static function getExpectedKEKSize(): int
    {
        return 16;
    }
}
