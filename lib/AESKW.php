<?php

namespace AESKW;

abstract class AESKW
{
    /**
     * The initial value used to wrap the key and check the integrity when unwrapped.
     * The RFC3394 set this value to 0xA6A6A6A6A6A6A6A6
     * @return string
     * @see https://tools.ietf.org/html/rfc3394#section-2.2.3.1
     */
    protected function getInitialValue()
    {
        return hex2bin("A6A6A6A6A6A6A6A6");
    }

    /**
     * @param  string                    $kek The Key Encryption Key
     * @throws \InvalidArgumentException If the size of the KEK is invalid
     */
    protected function checkKeySize($kek)
    {
        if (0 !== strlen($kek)% 8) {
            throw new \InvalidArgumentException("Bad key size");
        }
    }

    /**
     * @param string $kek  The Key Encryption Key
     * @param string $data Data to wrap
     */
    public function wrap($kek, $data)
    {
        $this->checkKeySize($kek);
        $A = $this->getInitialValue();
        $P = str_split($data, 8);
        $N = count($P);
        $C = array();
        if (1 === $N) {
            $B = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $kek, $A.$P[0], MCRYPT_MODE_ECB);
            $C[0] = $this->getMSB($B);
            $C[1] = $this->getLSB($B);
        } elseif (1 < $N) {
            $R = $P;
            for ($j = 0; $j <= 5; $j++) {
                for ($i = 1; $i <= $N; $i++) {
                    $B = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $kek, $A.$R[$i-1], MCRYPT_MODE_ECB);
                    $t = $i + $j*$N;
                    $A = $this->to64Bits($t) ^ $this->getMSB($B);
                    $R[$i-1] = $this->getLSB($B);
                }
            }
            $C = array_merge(array($A), $R);
        }

        return implode("", $C);
    }

    /**
     * @param string $kek  The Key Encryption Key
     * @param string $data Data to unwrap
     */
    public function unwrap($kek, $data)
    {
        $this->checkKeySize($kek);
        $P = str_split($data, 8);
        $A = $P[0];
        $N = count($P);

        if (1 >= $N) {
            throw new \InvalidArgumentException("Bad data");
        } elseif (2 === $N) {
            $B = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $kek, $P[0].$P[1], MCRYPT_MODE_ECB);
            if ($this->getInitialValue() !== $this->getMSB($B)) {
                throw new \RuntimeException("Integrity check failed");
            }

            return $this->getLSB($B);
        } else {
            $R = $P;
            for ($j = 5; $j >= 0; $j--) {
                for ($i = $N-1; $i >= 1; $i--) {
                    $t = $i + $j*($N-1);
                    $B = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $kek, ($this->to64Bits($t) ^ $A).$R[$i], MCRYPT_MODE_ECB);
                    $A = $this->getMSB($B);
                    $R[$i] = $this->getLSB($B);
                }
            }
            if ($A !== $this->getInitialValue()) {
                throw new \RuntimeException("Integrity check failed");
            }
            unset($R[0]);

            return implode("", $R);
        }
    }

    /**
     * @param  string $value
     * @return string
     */
    private function to64Bits($value)
    {
        return hex2bin(str_pad(dechex($value), 16, "0", STR_PAD_LEFT));
    }

    /**
     * @param  string $value
     * @return string
     */
    private function getMSB($value)
    {
        return substr($value, 0, strlen($value)/2);
    }

    /**
     * @param  string $value
     * @return string
     */
    private function getLSB($value)
    {
        return substr($value, strlen($value)/2);
    }
}
