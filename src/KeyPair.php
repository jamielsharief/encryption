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
namespace Encryption;

class KeyPair
{
    private $publicKey;
    private $privateKey;
    
    public function __construct(string $publicKey, string $privateKey)
    {
        $this->publicKey = trim($publicKey);
        $this->privateKey = trim($privateKey);
    }

    /**
     * Gets the Public Key from the KeyPair, this you can make publically
     * available as this is used to encrypt the messages.
     *
     * @return string
     */
    public function publicKey() : string
    {
        return $this->publicKey;
    }

    /**
    * Gets the Private Key from the KeyPair, this should be private at
    * all times, this is used to decrypt the messages.
    *
    * @return string
    */
    public function privateKey() : string
    {
        return $this->privateKey;
    }

    /**
     * Gets the public key fingerprint
     *
     * @return string e.g. D52A E482 CBE7 BB75 0148  3851 93A3 910A 0719 994D
     */
    public function fingerprint() : string
    {
        return (new AsymmetricEncryption)->fingerprint($this->publicKey);
    }

    /**
     * Exports the public key (and private key)
     *
     * @param string $file
     * @param boolean $includePrivateKey
     * @return boolean
     */
    public function export(string $file, bool $includePrivateKey = false) : bool
    {
        $out = $includePrivateKey ? $this->publicKey . PHP_EOL . $this->privateKey : $this->publicKey;
        return file_put_contents($file, $out);
    }
}
