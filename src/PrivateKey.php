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

class PrivateKey extends BaseKey
{
    /**
     * @var string
     */
    protected $privateKey;

    /**
     * @param string $privateKey
     * @param array $options The following options keys are supported
     *  - passphrase: default:null The password used to encrypt this key
     */
    public function __construct(string $privateKey, array $options = [])
    {
        $options += ['passphrase' => null, 'OAEPpadding' => true];
        $this->useOAEPPadding = $options['OAEPpadding'];

        $this->key = openssl_pkey_get_private($privateKey, $options['passphrase'] ?: '');
        if (! $this->key) {
            throw new EncryptionException('Invalid Private Key');
        }
        // SECURITY: keep copy of original key since using the passphrase will decrypt an encrypted key
        $this->privateKey = $privateKey;
    }

    /**
     * Loads a key from a file, if the file does not exist then it will throw a
     * NotFoundException.
     *
     * @param string $path
     * @param array $options The following options keys are supported
     *  - passphrase: default:null The password used to encrypt this key
     * @return \Encryption\PrivateKey
     */
    public static function load(string $path, array $options = []): PrivateKey
    {
        $options += ['passphrase' => null];

        if (! file_exists($path)) {
            throw new NotFoundException("'{$path}' not found");
        }

        return new PrivateKey(file_get_contents($path), $options);
    }

    /**
     * Generates a new private key and returns as PrivateKey object
     *
     * @see https://www.php.net/manual/en/function.openssl-csr-new.php
     * @param array $options The following options keys are supported
     *   - size: default: 4096. Key sizes e.g 1024,2048,3072,4096
     *   - passphrase: An optional passphrase to use for the private key
     *   - algo:  default: sha512. digest algo. see openssl_get_md_methods()
     *
     * @return \Encryption\PrivateKey
     */
    public static function generate(array $options = []): PrivateKey
    {
        $options += ['size' => 4096, 'passphrase' => null,'algo' => 'sha512'];
        
        $keyPair = openssl_pkey_new([
            'private_key_bits' => (int) $options['size'],
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'digest_alg' => $options['algo'],
            'encrypt_key' => $options['passphrase'] !== null
        ]);

        openssl_pkey_export($keyPair, $privateKey, $options['passphrase']);

        return new PrivateKey($privateKey, $options);
    }

    /**
     * Encrypts the data using the private key
     *
     * @param string $data
     * @param array $options The following options keys are supported
     *  - addBoundaries: default:true wraps contents of encrypted data between ENCRYPTED DATA
     * @return string
     */
    public function encrypt(string $data, array $options = []): string
    {
        $options += ['addBoundaries' => true];
        openssl_private_encrypt($data, $encrypted, $this->key);
        if ($encrypted === null) {
            throw new EncryptionException('Unable to encrypt data with key');
        }

        return $this->doEncrypt($encrypted, $options['addBoundaries']);
    }

    /**
    * Decrypts data that was encrypted with a public key. It removes the boundaries and base64 decodes
    * the encrypted string back to binary.
    *
    * @param string $encrypted
    * @return string
    * @throws \Encryption\Exception\EncryptionException
    */
    public function decrypt(string $encrypted): string
    {
        $encrypted = base64_decode($this->removeBoundaries($encrypted));

        openssl_private_decrypt($encrypted, $decrypted, $this->key, $this->padding());
        if ($decrypted === null) {
            throw new EncryptionException('Unable to decrypt data with key');
        }

        return $decrypted;
    }

    /**
     * Signs the data
     *
     * @param string $data
     * @param array $options The following options keys are supported
     *  - addBoundaries: default:true ----- SIGNATURE -----
     *  - algo: default:sha256 Algo to be used to verify signature @see openssl_get_md_methods
     * @return string
     * @throws \Encryption\Exception\EncryptionException
     */
    public function sign(string $data, array $options = []): string
    {
        $options += ['addBoundaries' => true,'algo' => 'sha256'];
        openssl_sign($data, $signature, $this->key, $options['algo']);
        $signature = base64_encode($signature);

        return $options['addBoundaries'] ? $this->addBoundaries($signature, 'SIGNATURE')  :  $signature;
    }

    /**
     * Extracts the public key
     *
     * @return \Encryption\PublicKey
     */
    public function extractPublicKey(): PublicKey
    {
        $keyDetails = openssl_pkey_get_details($this->key);

        return new PublicKey($keyDetails['key']);
    }

    /**
    * Converts the key object to a string
    *
    * SECURITY: Keys using passphrases are decrypted
    *
    * @return string
    */
    public function toString(): string
    {
        return $this->privateKey;
    }
}
