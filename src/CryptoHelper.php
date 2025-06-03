<?php
namespace CryptoWhatsapp;

class CryptoHelper
{
    /**
     * Возвращает зашифрованную строку используя метод шифрования 'AES-256-CBC'.
     *
     * @param string $data
     * @param string $key
     * @param string $iv
     * @return string|false
     */
    public static function encrypt(string $data, string $key, string $iv)
    {
        return openssl_encrypt($data, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    }

    /**
     * Возвращает расшифрованную строку используя метод шифрования 'AES-256-CBC'.
     *
     * @param string $data
     * @param string $key
     * @param string $iv
     * @return string
     */
    public static function decrypt(string $data, string $key, string $iv): string
    {
        return openssl_decrypt($data, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    }

    /**
     * @return string
     */
    public static function hmacSha256Truncated(string $key, string $data): string
    {
        return substr(hash_hmac('sha256', $data, $key, true), 0, 10);
    }
}
