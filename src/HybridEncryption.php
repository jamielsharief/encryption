<?php
/**
 * Encryption
 * Copyright 2020-2021 Jamiel Sharief.
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

/**
 * Hybrid encryption system (NEW)
 *
 * @internal right now have to base64 encode/decode, in future
 *
 * @see https://en.wikipedia.org/wiki/Hybrid_cryptosystem
 * @see https://paragonie.com/blog/2016/12/everything-you-know-about-public-key-encryption-in-php-is-wrong#hybrid-cryptosystems
 */
class HybridEncryption
{
    use EncryptionTrait;

    /**
     * Encrypts using hybrid encryption
     *
     * @param string $data
     * @param Encrpytion\PublicKey|Encrpytion\PrivateKey $key
     * @return string
     */
    public function encrypt(string $data, BaseKey $key, array $options = []): string
    {
        $options += ['addBoundaries' => true];

        $symmetric = new SymmetricEncryption();
       
        $sessionKey = $symmetric->generateKey();
  
        return $this->doEncrypt(
            base64_decode($key->encrypt($sessionKey, ['addBoundaries' => false])).
            base64_decode($symmetric->encrypt($data, $sessionKey)),
            $options['addBoundaries']
        );
    }

    /**
     * Decrypts data
     *
     * @param string $data
     * @param Encrpytion\PublicKey|Encrpytion\PrivateKey $key
     * @return string
     */
    public function decrypt(string $data, BaseKey $key): string
    {
        $data = base64_decode($this->removeBoundaries($data));

        $length = $key->bits() / 8;

        $sessionKey = base64_encode(substr($data, 0, $length));
        $data = base64_encode(substr($data, $length));

        return (new SymmetricEncryption())->decrypt($data, $key->decrypt($sessionKey));
    }
}
