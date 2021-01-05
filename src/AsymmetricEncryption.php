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
 * Asymmetric Encryption (DO NOT USE ANYMORE)
 *
 * IMPORTANT: This class is maintained for backwards comptability but has a security
 * issue re: OAEP padding. Migrate any data and code to use PrivateKey and PublicKey objects.
 *
 * @see https://paragonie.com/blog/2016/12/everything-you-know-about-public-key-encryption-in-php-is-wrong
 * @see https://tools.ietf.org/html/rfc7468
 */
class AsymmetricEncryption
{
    /**
     * Encrypts a string. Data is encrypted with OpenSSL, and the encrypted binary data
     * is base64 encoded
     *
     * @security OAEPpadding is disabled in this wrapper for backwards comptability.
     *
     * @param string $data
     * @param string $publicKey
     * @param boolean $addBoundaries
     * @return string
     */
    public function encrypt(string $data, string $publicKey, bool $addBoundaries = true): string
    {
        return (new PublicKey($publicKey, ['OAEPpadding' => false]))->encrypt($data, ['addBoundaries' => $addBoundaries]);
    }

    /**
     * Decrypts an encrypted string. It removes the boundaries and base64 decodes the encrypted
     * string back to binary.
     *
     * @security OAEPpadding is disabled in this wrapper for backwards comptability.
     *
     * @param string $encrypted
     * @param string $privateKey
     * @param string $passphrase
     * @return string
     * @throws \Encryption\Exception\EncryptionException
     */
    public function decrypt(string $encrypted, string $privateKey, string $passphrase = null): string
    {
        return (new PrivateKey($privateKey, ['passphrase' => $passphrase,'OAEPpadding' => false]))->decrypt($encrypted);
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

        return KeyPair::generate($options);
    }

    /**
     * Generates a new private key.
     *
     * @param array $options The following options keys are supported
     *   - size: default: 2048. Key sizes e.g 1024,2048,3072,4096
     *   - passphrase: An optional passphrase to use for the private key
     *   - algo:  default: sha512. digest algo. see openssl_get_md_methods()
     *
     * @return string
     */
    public function generatePrivateKey(array $options = []): string
    {
        $options += ['size' => 2048, 'passphrase' => null,'algo' => 'sha512'];

        return (string) PrivateKey::generate($options);
    }

    /**
     * Extracts a public key from a private key
     *
     * @param string $privateKey
     * @param string $passphrase
     * @return string
     */
    public function extractPublicKey(string $privateKey, string $passphrase = null): string
    {
        return (string) (new PrivateKey($privateKey, ['passphrase' => $passphrase]))->extractPublicKey();
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
        return (new PrivateKey($privateKey, ['passphrase' => $passphrase]))->sign($data, ['addBoundaries' => true]);
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
        return (new PublicKey($publicKey))->verify($data, $signature);
    }

    /**
     * Generates the fingerprint for a public key
     *
     * @return string e.g. D52A E482 CBE7 BB75 0148  3851 93A3 910A 0719 994D
     */
    public function fingerprint(string $publicKey): string
    {
        return (new PublicKey($publicKey))->fingerprint();
    }
}
