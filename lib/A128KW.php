<?php

namespace AESKW;

class A128KW extends AESKW
{
    protected function checkKeySize($kek)
    {
        parent::checkKeySize($kek);
        if (strlen($kek) !== 16) {
            throw new \InvalidArgumentException("Bad key size");
        }
    }
}
