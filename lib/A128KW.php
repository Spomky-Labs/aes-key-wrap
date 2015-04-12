<?php

namespace AESKW;

class A128KW
{
	use AESKW;
	
    /**
     * @param string $kek The Key Encryption Key
     *
     * @throws \InvalidArgumentException If the size of the KEK is invalid
     */
    protected static function checkKEKSize($kek)
    {
        if (strlen($kek) !== 16) {
            throw new \InvalidArgumentException("Bad KEK size");
        }
    }
}
