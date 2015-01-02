<?php

namespace AESKW;

class A192KW extends AESKW
{
    protected function checkKeySize($kek)
    {
        parent::checkKeySize($kek);
        if (strlen($kek) !== 24) {
            throw new \InvalidArgumentException("Bad key size");
        }
    }
}
