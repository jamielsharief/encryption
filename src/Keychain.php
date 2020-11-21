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

use DocumentStore\Document;
use InvalidArgumentException;
use DocumentStore\DocumentStore;
use Encryption\Exception\NotFoundException;
use Encryption\Exception\EncryptionException;

class Keychain
{

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
     *  - size: default:4096. Key sizes e.g 1024,2048,3072,4096
     *  - passphrase: An optional passphrase to use for the private key
     *  - algo:  default: sha512. digest algo. see openssl_get_md_methods()
     *  - expires: a strtotime compatible string on when the key can be used until
     *  - comment: additional information can be put here
     * @return bool
     */
    public function create(string $name, array $options = []): bool
    {
        $options += ['size' => 4096];
       
        return $this->add($name, (string) PrivateKey::generate($options), $options);
    }

    /**
     * Adds private/public key to the Keychain
     *
     * @param string $name
     * @param string $key
     * @param array $options The following options keys are supported
     *  - expires: a strtotime compatible string on when the key can be used until
     *  - comment: additional info
     * @return bool
     */
    public function add(string $name, string $key, array $options = []): bool
    {
        $options += ['expires' => null,'comment' => null];

        $keyPair = $this->fromString($key); // remove line endings

        if ($keyPair['private'] && empty($keyPair['public'])) {
            $keyPair['public'] = (new PrivateKey($keyPair['private']))->extractPublicKey()->toString();
        }

        $document = new Document([
            'id' => $this->keyId($name),
            'name' => $name,
            'privateKey' => $keyPair['private'],
            'publicKey' => $keyPair['public'],
            'fingerprint' => (new PublicKey($keyPair['public']))->fingerprint(),
            'expires' => $options['expires'] ? date('Y-m-d H:i:s', strtotime($options['expires'])) : null,
            'type' => empty($keyPair['private']) ? 'public-key' : 'key-pair',
            'comment' => $options['comment'],
            'created' => date('Y-m-d H:i:s')
        ]);

        return $this->documentStore->set($name, $document);
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
        if (! file_exists($keyFile)) {
            throw new NotFoundException('File does not exist');
        }
 
        return $this->add($name, file_get_contents($keyFile), $options);
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

    /**
     * Parses a key or key pair into an array, different key types have different boundaries
     * e.g. BEGIN PRIVATE KEY, BEGIN ENCRYPTED PRIVATE KEY (with passphrase)
     *
     * @link https://blog.programster.org/key-file-formats
     *
     * @param string $string
     * @return array
     */
    protected function fromString(string $string): array
    {
        $string = trim($string);
            
        $out = [];
        $current = '';
        foreach (explode("\n", $string) as $line) {
            $current .= $line . PHP_EOL;
            if (strpos($line, '-----END') !== false && strpos($current, '-----BEGIN') !== false) {
                $out[] = trim($current);
                $current = '';
            }
        }
    
        $found = count($out);
        if ($found < 1 || $found > 2) {
            throw new EncryptionException('Invalid key or keys');
        }
    
        $privateKey = $publicKey = null;
        foreach ($out as $key) {
            if (strpos($key, 'PUBLIC KEY') !== false) {
                $publicKey = $key;
            } elseif (strpos($key, 'PRIVATE KEY') !== false) {
                $privateKey = $key;
            }
        }
    
        return [
            'private' => $privateKey,
            'public' => $publicKey
        ];
    }
}
