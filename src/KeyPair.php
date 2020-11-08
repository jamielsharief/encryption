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
    private $privateKey;
    private $publicKey;
    
    /**
     * @param string $privateKey
     * @param string $publicKey
     */
    public function __construct(string $privateKey, string $publicKey)
    {
        $this->privateKey = trim($privateKey);
        $this->publicKey = trim($publicKey);
    }

    /**
     * Gets the Public Key from the KeyPair, this you can make publically
     * available as this is used to encrypt the messages.
     *
     * @return string
     */
    public function publicKey(): string
    {
        return $this->publicKey;
    }

    /**
    * Gets the Private Key from the KeyPair, this should be private at
    * all times, this is used to decrypt the messages.
    *
    * @return string
    */
    public function privateKey(): string
    {
        return $this->privateKey;
    }

    /**
     * Gets the public key fingerprint
     *
     * @return string e.g. D52A E482 CBE7 BB75 0148 3851 93A3 910A 0719 994D
     */
    public function fingerprint(): string
    {
        return (new AsymmetricEncryption)->fingerprint($this->publicKey);
    }

    /**
     * Converts the KeyPair to a string
     *
     * @return string
     */
    public function toString(): string
    {
        return $this->privateKey . PHP_EOL . $this->publicKey;
    }

    /**
     * @return string
     */
    public function __toString()
    {
        return $this->toString();
    }
}
