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

use Encryption\Exception\NotFoundException;
use Encryption\Exception\EncryptionException;

class PublicKey extends BaseKey
{
    /**
     * @param string $publicKey
     * @param array $options
     */
    public function __construct(string $publicKey, array $options = [])
    {
        $options += ['OAEPpadding' => true];
        $this->useOAEPPadding = $options['OAEPpadding'];

        $this->key = openssl_pkey_get_public($publicKey);
        if (! $this->key) {
            throw new EncryptionException('Invalid Private Key');
        }
    }

    /**
     * Loads a key from a file, if the file does not exist then it will throw a
     * NotFoundException.
     *
     * @param string $path
     * @return \Encryption\PublicKey
     */
    public static function load(string $path): PublicKey
    {
        if (! file_exists($path)) {
            throw new NotFoundException("'{$path}' not found");
        }

        return new PublicKey(file_get_contents($path));
    }

    /**
     * Encrypts the data using the public key
     *
     * @param string $data
     * @param array $options The following options keys are supported
     *  - addBoundaries: default:false wraps contents of encrypted data between ENCRYPTED DATA (this will be removed)
     * @return string
     */
    public function encrypt(string $data, array $options = []): string
    {
        $options += ['addBoundaries' => false];
        
        if (mb_strlen($data) > $this->maxEncryptSize()) {
            throw new EncryptionException('Data is too long');
        }
     
        openssl_public_encrypt($data, $encrypted, $this->key, $this->padding());
        if ($encrypted === null) {
            throw new EncryptionException('Unable to encrypt data with key');
        }

        return $this->doEncrypt($encrypted, $options['addBoundaries']);
    }

    /**
    * Decrypts data that was encrypted with a private key. It removes the boundaries and base64 decodes
    * the encrypted string back to binary.
    *
    * @param string $encrypted
    * @return string
    * @throws \Encryption\Exception\EncryptionException
    */
    public function decrypt(string $encrypted): string
    {
        $encrypted = base64_decode($this->removeBoundaries($encrypted));

        openssl_public_decrypt($encrypted, $decrypted, $this->key);
        if ($decrypted === null) {
            throw new EncryptionException('Unable to decrypt data with key');
        }

        return $decrypted;
    }

    /**
     * Generates the fingerprint for a public key
     *
     * @return string e.g. D52A E482 CBE7 BB75 0148 3851 93A3 910A 0719 994D
     */
    public function fingerprint(): string
    {
        $data = $this->removeBoundaries($this->toString());
        $fingerprint = strtoupper(hash('sha1', $data));

        return trim(chunk_split($fingerprint, 4, ' '));
    }

    /**
     * Verifies that signature against data
     *
     * @param string $data
     * @param string $signature
     * @param array $options The following options keys are supported
     *  - algo: default:sha256 Algo to be used to verify signature @see openssl_get_md_methods
     * @return boolean
     */
    public function verify(string $data, string $signature, array $options = []): bool
    {
        $options += ['algo' => 'sha256'];

        $signature = $this->removeBoundaries($signature);

        return openssl_verify($data, base64_decode($signature), $this->key, $options['algo']) === 1;
    }

    /**
     * Converts the key object to a string
     *
     * @return string
     */
    public function toString(): string
    {
        $details = openssl_pkey_get_details($this->key);

        return $details['key'];
    }
}
