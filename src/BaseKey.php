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

abstract class BaseKey
{
    use EncryptionTrait;
    
    /**
     * Should be true, this is only here for backwards compatability
     *
     * @see https://paragonie.com/blog/2016/12/everything-you-know-about-public-key-encryption-in-php-is-wrong
     * @see https://rules.sonarsource.com/php/type/Vulnerability/RSPEC-2277
     *
     * @var boolean
     */
    protected $useOAEPPadding = true;

    /**
     * @var resource|false
     */
    protected $key;

    /**
     * Encrypts the data using the private key
     *
     * @param string $data
     * @param array $options The following options keys are supported
     *  - addBoundaries: default:true wraps contents of encrypted data between ENCRYPTED DATA
     * @return string
     */
    abstract public function encrypt(string $data, array $options = []): string;

    /**
     * Decrypts an encrypted string. It removes the boundaries and base64 decodes the encrypted
     * string back to binary before decrypting.
     *
     * @param string $encrypted
     * @return string
     * @throws \Encryption\Exception\EncryptionException
     */
    abstract public function decrypt(string $encrypted): string;

    /**
     * Converts the key object to a string
     *
     * @return string
     */
    abstract public function toString(): string;

    /**
     * Magic method
     *
     * @return string
     */
    public function __toString()
    {
        return $this->toString();
    }

    /**
     * Gets the key size in bits
     *
     * @return integer
     */
    public function bits(): int
    {
        return (int) openssl_pkey_get_details($this->key)['bits'];
    }

    /**
     * @see https://www.openssl.org/docs/manmaster/man3/RSA_public_encrypt.html
     * @return integer
     */
    protected function maxEncryptSize(): int
    {
        if ($this->useOAEPPadding) {
            return $this->bits() / 8 - 42;
        }

        return $this->bits() / 8 - 11;
    }

    /**
    * Padding option to handle backwards comptability.
    *
    * @deprecated This will be removed in version 2, its for backwards compatability. This
    * tag has been added as reminder.
    * @return int
    */
    protected function padding(): int
    {
        return $this->useOAEPPadding ? OPENSSL_PKCS1_OAEP_PADDING : OPENSSL_PKCS1_PADDING;
    }
}
