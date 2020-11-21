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

class KeyPair
{
    /**
     * @var string
     */
    private $privateKey;

    /**
     * @var string
     */
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
       * Generates a new private and public key. The public key is used for encryption, this what
       * you give to other people. The private key is used for decryption, this you keep safe and
       * is only for you.
       *
       * @param array $options The following options keys are supported
       *   - size: default: 4096. Key sizes e.g 1024,2048,3072,4096
       *   - passphrase: An optional passphrase to use for the private key
       *   - algo:  default: sha512. digest algo. see openssl_get_md_methods()
       *
       * @return \Encryption\KeyPair
       */
    public static function generate(array $options = []): KeyPair
    {
        $options += ['size' => 4096, 'passphrase' => null,'algo' => 'sha512'];

        $privateKey = PrivateKey::generate($options);
        $publicKey = $privateKey->extractPublicKey();

        return new KeyPair((string) $privateKey, (string) $publicKey);
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
        return (new PublicKey($this->publicKey))->fingerprint();
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
