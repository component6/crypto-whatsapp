<?php
namespace CryptoWhatsapp;

class Hkdf
{
    /**
     * Создает расширенный ключ с использованием HKDF с SHA-256.
     *
     * @param string $key
     * @param string $info
     * @param int $length
     * @return string
     */
    public static function makeExpandedKey(string $key, string $info, int $length = 112): string
    {
        $hashLength = 32;
        $n          = (int) ceil($length / $hashLength);

        $okm = '';
        $t   = '';

        for ($i = 1; $i <= $n; $i++) {
            $t   = hash_hmac('sha256', $t . $info . chr($i), $key, true);
            $okm .= $t;
        }

        return substr($okm, 0, $length);
    }
}
