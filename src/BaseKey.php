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

    const BOUNDARY_PATTERN = "#-----\r?\n(.*)\r?\n-----#s";

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
     * @param string $encrypted
     * @param boolean $addBoundaries
     * @return string
     */
    protected function doEncrypt(string $encrypted, bool $addBoundaries): string
    {
        $encoded = base64_encode($encrypted);

        return $addBoundaries ? $this->addBoundaries($encoded, 'ENCRYPTED DATA') :  $encoded ;
    }

    /**
     * Adds the boundaries to an encrypted string
     *
     * @param string $data
     * @return string
     */
    protected function addBoundaries(string $data, string $boundary): string
    {
        return "-----BEGIN {$boundary}-----\n" . $data  . "\n-----END {$boundary}-----";
    }

    /**
     * Removes the BEGIN/END ENCRYPTED DATA boundaries.
     * TODO: remove
     * @param string $data
     * @return string
     */
    protected function removeBoundaries(string $data): string
    {
        preg_match(self::BOUNDARY_PATTERN, $data, $matches);
        if ($matches) {
            $data = $matches[1];
        }

        return $data;
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
