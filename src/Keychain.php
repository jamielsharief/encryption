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

use DocumentStore\Document;
use InvalidArgumentException;
use DocumentStore\DocumentStore;
use Encryption\Exception\NotFoundException;

class Keychain
{
    use EncryptionTrait;
    /**
     * Database
     *
     * @var \DocumentStore\DocumentStore
     */
    private $documentStore;

    /**
     * @param string $directory path to directory where keys are stored
     */
    public function __construct(string $directory)
    {
        if (! is_dir($directory)) {
            throw new InvalidArgumentException('Path does not exist');
        }
        $this->documentStore = new DocumentStore($directory);
    }

    /**
     * Gets the Key ID from a name of key e.g. username, email etc
     */
    public function keyId(string $name): string
    {
        return md5(hash('sha256', $name));
    }

    /**
     * Creates a new KeyPair and adds to the Keychain
     *
     * @param string $name
     * @param array $options The following options keys are supported
     *  - size: default: 2048. Key sizes e.g 1024,2048,3072,4096
     *  - passphrase: An optional passphrase to use for the private key
     *  - algo:  default: sha512. digest algo. see openssl_get_md_methods()
     *  - expires: a strtotime compatible string on when the key can be used until
     *  - comment: additional information can be put here
     * @return bool
     */
    public function create(string $name, array $options = []): bool
    {
        $keyPair = (new AsymmetricEncryption())->generateKeyPair($options);

        $tmpFile = sys_get_temp_dir() . '/' . uniqid() .'.tmp';
        file_put_contents($tmpFile, (string) $keyPair);

        $this->import($name, $tmpFile, $options);

        return $this->documentStore->has($name);
    }

    /**
     * Checks if a Key exists in the Keychain
     *
     * @param string $name
     * @return boolean
     */
    public function has(string $name): bool
    {
        return $this->documentStore->has($name);
    }

    /**
     * Imports an item into the Keychain
     *
     * @param string $name A unique name which you will use to lookup values, e.g. username, email address or UUID etc
     * @param string $keyFile path to key public key or private/public key file
     * @param array $options The following options keys are supported
     *  - expires: a strtotime compatible string on when the key can be used until
     *  - comment: additional info
     * @return bool
     */
    public function import(string $name, string $keyFile, array $options = []): bool
    {
        $options += ['expires' => null,'comment' => null];

        if (! file_exists($keyFile)) {
            throw new NotFoundException('File does not exist');
        }
        $keyData = file_get_contents($keyFile);
        $keyPair = $this->fromString($keyData); // remove lineendings

        $document = new Document([
            'id' => $this->keyId($name),
            'name' => $name,
            'privateKey' => $keyPair['private'],
            'publicKey' => $keyPair['public'],
            'fingerprint' => $keyPair['public'] ? (new AsymmetricEncryption)->fingerprint($keyPair['public']) : null,
            'expires' => $options['expires'] ? date('Y-m-d H:i:s', strtotime($options['expires'])) : null,
            'type' => empty($keyPair['private']) ? 'public-key' : 'key-pair',
            'comment' => $options['comment'],
            'created' => date('Y-m-d H:i:s')
        ]);

        return $this->documentStore->set($name, $document);
    }

    /**
     * Gets the meta data for a key
     *
     * @param string $name name of key, e.g. username, email, UUID etc
     * @return \DocumentStore\Document
     */
    public function get(string $name): Document
    {
        try {
            return $this->documentStore->get($name);
        } catch (\DocumentStore\Exception\NotFoundException $exception) {
            throw new NotFoundException("{$name} was not found");
        }
    }

    /**
     * Returns a list of Key IDs in the Keychain
     *
     * @return array
     */
    public function list(): array
    {
        return $this->documentStore->list('', false);
    }

    /**
     * Deletes a Key from the Keychain
     *
     * @param string $name
     * @return boolean
     */
    public function delete(string $name): bool
    {
        try {
            return $this->documentStore->delete($name);
        } catch (\DocumentStore\Exception\NotFoundException $exception) {
            throw new NotFoundException("{$name} was not found");
        }
    }
}
