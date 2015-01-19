<?php

namespace AESKW;

class A256KW extends AESKW
{
    protected function checkKEKSize($kek)
    {
        parent::checkKEKSize($kek);
        if (strlen($kek) !== 32) {
            throw new \InvalidArgumentException("Bad KEK size");
        }
    }
}
