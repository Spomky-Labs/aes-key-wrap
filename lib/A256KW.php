<?php

namespace AESKW;

class A256KW extends AESKW
{
    protected function checkKeySize($kek)
    {
        parent::checkKeySize($kek);
        if (strlen($kek) !== 32) {
            throw new \InvalidArgumentException("Bad key size");
        }
    }
}
