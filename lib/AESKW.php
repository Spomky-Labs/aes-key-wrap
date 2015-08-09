<?php

namespace AESKW;

trait AESKW
{
    /**
     * The initial value used to wrap the key and check the integrity when unwrapped.
     * The RFC3394 set this value to 0xA6A6A6A6A6A6A6A6
     * The RFC5649 set this value to 0xA65959A6XXXXXXXX (The part with XXXXXXXX is the MLI, depends on the padding).
     *
     * @param string $key             The key
     * @param bool   $padding_enabled Enable padding (RFC5649)
     *
     * @return string
     *
     * @see https://tools.ietf.org/html/rfc3394#section-2.2.3.1
     */
    private static function getInitialValue(&$key, $padding_enabled)
    {
        if (false === $padding_enabled) {
            return hex2bin('A6A6A6A6A6A6A6A6');
        }

        $MLI = strlen($key);
        $iv = hex2bin('A65959A6').self::toXBits(32, $MLI);

        $n = intval(ceil($MLI / 8));
        $key = str_pad($key, 8 * $n, "\0", STR_PAD_RIGHT);

        return $iv;
    }

    /**
     * @param string $key
     * @param bool   $padding_enabled
     * @param string $iv
     *
     * @return bool
     */
    private static function checkInitialValue(&$key, $padding_enabled, $iv)
    {
        // RFC3394 compliant
        if ($iv === hex2bin('A6A6A6A6A6A6A6A6')) {
            return true;
        }

        // The RFC3394 is required but the previous check is not satisfied => invalid
        if (false === $padding_enabled) {
            return false;
        }

        // The high-order half of the AIV according to the RFC5649
        if (hex2bin('A65959A6') !== self::getMSB($iv)) {
            return false;
        }

        $n = strlen($key) / 8;
        $MLI = hexdec(bin2hex(ltrim(self::getLSB($iv), "\0")));

        if (!(8 * ($n - 1) < $MLI && $MLI <= 8 * $n)) {
            return false;
        }

        $b = 8 * $n - $MLI;
        for ($i = 0; $i < $b; ++$i) {
            if ("\0" !== substr($key, $MLI + $i, 1)) {
                return false;
            }
        }
        $key = substr($key, 0, $MLI);

        return true;
    }

    /**
     * @param string $key             The Key to wrap
     * @param bool   $padding_enabled
     *
     * @throws \InvalidArgumentException If the size of the Key is invalid
     */
    private static function checkKeySize($key, $padding_enabled)
    {
        if (false === $padding_enabled && 0 !== strlen($key) % 8) {
            throw new \InvalidArgumentException('Bad key size');
        }
        if (1 > strlen($key)) {
            throw new \InvalidArgumentException('Bad key size');
        }
    }

    /**
     * @param string $kek             The Key Encryption Key
     * @param string $key             The key to wrap
     * @param bool   $padding_enabled If false, the key to wrap must be a sequence of one or more 64-bit blocks (RFC3394 compliant), else the key size must be at least one octet (RFC5649 compliant)
     *
     * @return string The wrapped key
     */
    public static function wrap($kek, $key, $padding_enabled = false)
    {
        self::checkKEKSize($kek);
        $A = self::getInitialValue($key, $padding_enabled);
        self::checkKeySize($key, $padding_enabled);
        $P = str_split($key, 8);
        $N = count($P);
        $C = [];
        if (1 === $N) {
            $B = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $kek, $A.$P[0], MCRYPT_MODE_ECB);
            $C[0] = self::getMSB($B);
            $C[1] = self::getLSB($B);
        } elseif (1 < $N) {
            $R = $P;
            for ($j = 0; $j <= 5; ++$j) {
                for ($i = 1; $i <= $N; ++$i) {
                    $B = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $kek, $A.$R[$i - 1], MCRYPT_MODE_ECB);
                    $t = $i + $j * $N;
                    $A = self::toXBits(64, $t) ^ self::getMSB($B);
                    $R[$i - 1] = self::getLSB($B);
                }
            }
            $C = array_merge([$A], $R);
        }

        return implode('', $C);
    }

    /**
     * @param string $kek             The Key Encryption Key
     * @param string $key             The key to unwrap
     * @param bool   $padding_enabled If false, the AIV check must be RFC3394 compliant, else it must be RFC5649 or RFC3394 compliant
     *
     * @throws \RuntimeException If the wrapped key is not valid
     *
     * @return string The key unwrapped
     */
    public static function unwrap($kek, $key, $padding_enabled = false)
    {
        self::checkKEKSize($kek);
        $P = str_split($key, 8);
        $A = $P[0];
        $N = count($P);

        if (1 >= $N) {
            throw new \RuntimeException('Bad data');
        } elseif (2 === $N) {
            $B = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $kek, $P[0].$P[1], MCRYPT_MODE_ECB);
            $unwrapped = self::getLSB($B);
            $A = self::getMSB($B);
        } else {
            $R = $P;
            for ($j = 5; $j >= 0; --$j) {
                for ($i = $N - 1; $i >= 1; --$i) {
                    $t = $i + $j * ($N - 1);
                    $B = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $kek, (self::toXBits(64, $t) ^ $A).$R[$i], MCRYPT_MODE_ECB);
                    $A = self::getMSB($B);
                    $R[$i] = self::getLSB($B);
                }
            }
            unset($R[0]);

            $unwrapped = implode('', $R);
        }
        if (!self::checkInitialValue($unwrapped, $padding_enabled, $A)) {
            throw new \RuntimeException('Integrity check failed');
        }

        return $unwrapped;
    }

    /**
     * @param int $bits
     * @param int $value
     *
     * @return string
     */
    private static function toXBits($bits, $value)
    {
        return hex2bin(str_pad(dechex($value), $bits / 4, '0', STR_PAD_LEFT));
    }

    /**
     * @param string $value
     *
     * @return string
     */
    private static function getMSB($value)
    {
        return substr($value, 0, strlen($value) / 2);
    }

    /**
     * @param string $value
     *
     * @return string
     */
    private static function getLSB($value)
    {
        return substr($value, strlen($value) / 2);
    }
}
