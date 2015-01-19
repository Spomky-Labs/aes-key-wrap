<?php

namespace AESKW;

class A192KW extends AESKW
{
    protected function checkKEKSize($kek)
    {
        parent::checkKEKSize($kek);
        if (strlen($kek) !== 24) {
            throw new \InvalidArgumentException("Bad KEK size");
        }
    }
}
