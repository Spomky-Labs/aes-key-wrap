<?php

namespace AESKW;

class A128KW extends AESKW
{
    protected function checkKEKSize($kek)
    {
        parent::checkKEKSize($kek);
        if (strlen($kek) !== 16) {
            throw new \InvalidArgumentException("Bad KEK size");
        }
    }
}
