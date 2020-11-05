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

use Encryption\Exception\EncryptionException;

/**
 * Asymmetric Encryption
 * @see https://tools.ietf.org/html/rfc7468
 */
class AsymmetricEncryption
{
    const BOUNDARY_PATTERN = "#-----\r?\n(.*)\r?\n-----#s";
    /**
     * Encrypts a string. Data is encrypted with OpenSSL, and the encrypted binary data
     * is base64 encoded
     *
     * @param string $data
     * @param string $publicKey
     * @return string
     */
    public function encrypt(string $data, string $publicKey): string
    {
        openssl_public_encrypt($data, $encrypted, $publicKey);
        if ($encrypted === null) {
            throw new EncryptionException('Unable to encrypt data with key');
        }

        return $this->addBoundaries(base64_encode($encrypted), 'ENCRYPTED DATA');
    }

    /**
     * Decrypts an encrypted string. It removes the boundaries and base64 decodes the encrypted
     * string back to binary.
     *
     * @param string $encrypted
     * @param string $privateKey
     * @param string $passphrase
     * @return string
     * @throws \Encryption\Exception\EncryptionException
     */
    public function decrypt(string $encrypted, string $privateKey, string $passphrase = null): string
    {
        $encrypted = $this->removeBoundaries($encrypted);
        $encrypted = base64_decode($encrypted);

        if ($passphrase) {
            $privateKey = openssl_get_privatekey($privateKey, $passphrase);
            if (! $privateKey) {
                throw new EncryptionException('Invalid passphrase');
            }
        }

        openssl_private_decrypt($encrypted, $decrypted, $privateKey);
        if ($decrypted === null) {
            throw new EncryptionException('Unable to decrypt data with key');
        }

        return $decrypted;
    }

    /**
    * Generates a new private and public key. The public key is used for encryption, this what
    * you give to other people. The private key is used for decryption, this you keep safe and
    * is only for you.
    *
    * @param array $options The following options keys are supported
    *   - size: default: 2048. Key sizes e.g 1024,2048,3072,4096
    *   - passphrase: An optional passphrase to use for the private key
    *   - algo:  default: sha512. digest algo. see openssl_get_md_methods()
    *
    * @return \Encryption\KeyPair
    */
    public function generateKeyPair(array $options = []): KeyPair
    {
        $options += ['size' => 2048, 'passphrase' => null,'algo' => 'sha512'];
     
        // @see https://www.php.net/manual/en/function.openssl-csr-new.php
        $keyPair = openssl_pkey_new([
            'private_key_bits' => (int) $options['size'],
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'digest_alg' => $options['algo'],
            'encrypt_key' => $options['passphrase'] !== null
        ]);

        openssl_pkey_export($keyPair, $privateKey, $options['passphrase']);
        $keyDetails = openssl_pkey_get_details($keyPair);

        return new KeyPair($keyDetails['key'], $privateKey);
    }

    /**
     * Signs the data
     *
     * @param string $data
     * @param string $privateKey
     * @param string $passphrase
     * @return string
     * @throws \Encryption\Exception\EncryptionException
     */
    public function sign(string $data, string $privateKey, string $passphrase = null): string
    {
        if ($passphrase) {
            $privateKey = openssl_get_privatekey($privateKey, $passphrase);
            if (! $privateKey) {
                throw new EncryptionException('Invalid passphrase');
            }
        }

        openssl_sign($data, $signature, $privateKey, OPENSSL_ALGO_SHA256);

        return $this->addBoundaries(base64_encode($signature), 'SIGNATURE');
    }

    /**
     * Verify a string that has been signed
     *
     * @param string $data
     * @param string $signature
     * @param string $publicKey
     * @return boolean
     */
    public function verify(string $data, string $signature, string $publicKey): bool
    {
        $signature = $this->removeBoundaries($signature);

        return openssl_verify($data, base64_decode($signature), $publicKey, 'sha256WithRSAEncryption');
    }

    /**
     * Generates the fingerprint for a public key
     *
     * @return string e.g. D52A E482 CBE7 BB75 0148  3851 93A3 910A 0719 994D
     */
    public function fingerprint(string $publicKey): string
    {
        preg_match(self::BOUNDARY_PATTERN, $publicKey, $matches);
        $fingerprint = strtoupper(hash('sha1', $matches[1]));

        return trim(chunk_split($fingerprint, 4, ' '));
    }

    /**
     * Adds the boundaries to an encrypted string
     *
     * @param string $data
     * @return string
     */
    private function addBoundaries(string $data, string $boundary): string
    {
        return "-----BEGIN {$boundary}-----\n" . $data  . "\n-----END {$boundary}-----";
    }

    /**
     * Removes the BEGIN/END ENCRYPTED DATA boundaries.
     *
     * @param string $data
     * @param string $boundary
     * @return string
     */
    private function removeBoundaries(string $data): string
    {
        preg_match(self::BOUNDARY_PATTERN, $data, $matches);
        if ($matches) {
            $data = $matches[1];
        }

        return $data;
    }
}
