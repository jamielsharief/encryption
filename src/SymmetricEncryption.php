<?php
/**
 * Encryption
 * Copyright 2020 Jamiel Sharief.
 *
 * Licensed under The MIT License
 * The above copyright notice and this permission notice shall be included in all copies or substantial
 * portions of the Software.
 *
 * @copyright   Copyright (c) Jamiel Sharief
 * @license     https://opensource.org/licenses/mit-license.php MIT License
 */
declare(strict_types = 1);
namespace Encryption;

use InvalidArgumentException;
use Encryption\Exception\EncryptionException;

/**
 * Symmetric Encryption
 * @see https://tools.ietf.org/html/rfc7468
 */
class SymmetricEncryption
{
    /**
     * Default Cipher is AES-256-CBC, key length 32 bytes.
     */
    const CIPHER = 'AES-256-CBC';

    /**
     * Encrypts a string using your key. The key should be secure use generateKey
     *
     * @see http://php.net/manual/en/function.openssl-encrypt.php
     * @param string $string
     * @param string $key must must be 256 bits (32 bytes)
     * @return string
     */
    public function encrypt(string $string, string $key): string
    {
        if (mb_strlen($key) !== 32) {
            throw new InvalidArgumentException('Key must be 256 bits (32 bytes)');
        }

        $length = openssl_cipher_iv_length(self::CIPHER);
        $iv = random_bytes($length);
        $raw = openssl_encrypt($string, self::CIPHER, $key, OPENSSL_RAW_DATA, $iv);
        $hmac = hash_hmac('sha256', $raw, $key, true);

        return base64_encode($iv . $hmac . $raw);
    }

    /**
     * Decrypts an encrypted string
     *
     * @param string $string
     * @param string $key must must be 256 bits (32 bytes)
     * @return string decrypted string
     * @throws \Encryption\Exception\EncryptionException
     */
    public function decrypt(string $string, string $key): string
    {
        if (mb_strlen($key) !== 32) {
            throw new InvalidArgumentException('Key must be 256 bits (32 bytes)');
        }

        $string = base64_decode($string);
        $length = openssl_cipher_iv_length(self::CIPHER);
        $iv = substr($string, 0, $length);
        $hmac = substr($string, $length, 32);
        $raw = substr($string, $length + 32);
        $expected = hash_hmac('sha256', $raw, $key, true);
       
        if ($this->compare($expected, $hmac)) {
            $decrypted = openssl_decrypt($raw, self::CIPHER, $key, OPENSSL_RAW_DATA, $iv);
            if ($decrypted) {
                return $decrypted;
            }
        }

        throw new EncryptionException('Unable to decrypt');
    }

    /**
     * Generates a secure 256 bits (32 bytes) key
     *
     * 62^8 = 2,272,657,884,496,799,923,276,216,267,898,815,945,334,186,617,388,524,371,968
     *
     * @return string
     */
    public static function generateKey(): string
    {
        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $out = '';
        for ($i = 0; $i < 32; $i++) {
            $out .= $characters[random_int(0, 61)];
        }

        return $out;
    }

    /**
     * Compares two strings are equal in a secure way to prevent timing attacks.
     *
     * @see https://blog.ircmaxell.com/2014/11/its-all-about-time.html
     *
     * @param string $original
     * @param string $compare
     * @return bool
     */
    protected function compare(string $original = null, string $compare = null): bool
    {
        if (! is_string($original) || ! is_string($compare)) {
            return false;
        }

        return hash_equals($original, $compare);
    }
}
