<?php
/**
 * Asymmetric Encryption Class
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

use Exception;

/**
 * Asymmetric Encryption
 * @see https://tools.ietf.org/html/rfc7468
 */
class AsymmetricEncryption
{
    /**
     * Encrypts a string. Data is encrypted with OpenSSL, and the encrypted binary data
     * is base64 encoded
     *
     * @param string $data
     * @param string $publicKey
     * @return string
     */
    public function encrypt(string $data, string $publicKey) : string
    {
        openssl_public_encrypt($data, $encrypted, $publicKey);
        if ($encrypted === null) {
            throw new Exception('Unable to encrypt data with key');
        }

        return $this->addBoundaries(base64_encode($encrypted));
    }

    /**
     * Decrypts an encrypted string. It removes the boundaries and base64 decodes the encrypted
     * string back to binary.
     *
     * @param string $encrypted
     * @param string $privateKey
     * @param string $password
     * @return string
     */
    public function decrypt(string $encrypted, string $privateKey, string $password = null) : string
    {
        $encrypted = $this->removeBoundaries($encrypted);
        $encrypted = base64_decode($encrypted);

        if ($password) {
            $privateKey = openssl_get_privatekey($privateKey, $password);
        }

        openssl_private_decrypt($encrypted, $decrypted, $privateKey);
        if ($decrypted === null) {
            throw new Exception('Unable to decrypt data with key');
        }

        return $decrypted;
    }

    /**
    * Generates a new private and public key. The public key is used for encryption, this what
    * you give to other people. The private key is used for decryption, this you keep safe and
    * is only for you.
    *
    * @param array $options The following options keys are supported
    *   algo:  default: sha512. digest algo. see openssl_get_md_methods()
    *   bits: default: 4096. the number of bits used to generate the private key.
    *   password: An optional passphrase to use for the private key
    *
    * @return \Encryption\KeyPair
    */
    public function generateKeyPair(array $options = []) : KeyPair
    {
        $options += ['algo' => 'sha512', 'bits' => 4096, 'password' => null];
     
        // @see https://www.php.net/manual/en/function.openssl-csr-new.php
        $keyPair = openssl_pkey_new([
            'digest_alg' => $options['algo'],
            'private_key_bits' => $options['bits'],
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'encrypt_key' => $options['password'] !== null
        ]);

        openssl_pkey_export($keyPair, $privateKey, $options['password']);
        $keyDetails = openssl_pkey_get_details($keyPair);

        return new KeyPair($keyDetails['key'], $privateKey);
    }

    /**
     * Adds the boundaries to an encrypted string
     *
     * @param string $data
     * @return string
     */
    private function addBoundaries(string $data) : string
    {
        return "-----BEGIN ENCRYPTED DATA-----\n" . $data  . "\n-----END ENCRYPTED DATA-----";
    }

    /**
     * Removes the BEGIN/END NECRYPTED DATA boundaries
     *
     * @param string $data
     * @return string
     */
    private function removeBoundaries(string $data) : string
    {
        if (substr($data, 0, 30) !== '-----BEGIN ENCRYPTED DATA-----' or substr($data, -28) !== '-----END ENCRYPTED DATA-----') {
            throw new Exception('Invalid encrypted data');
        }

        return substr($data, 31, -29);
    }
}
