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

use Encryption\Struct\Key;
use InvalidArgumentException;
use Encryption\Exception\NotFoundException;

class KeyChain
{
    private $path;

    /**
     * @param string $directory path to directory where keys are stored
     */
    public function __construct(string $directory)
    {
        if (! is_dir($directory)) {
            throw new InvalidArgumentException('Path does not exist');
        }
        $this->path = $directory;
    }

    /**
     * Gets the Key ID from a name of key e.g. username, email etc
     */
    public function keyId(string $name): string
    {
        return md5(hash('sha256', $name));
    }

    /**
     * Creates a new KeyPair and adds to the KeyChain
     *
     * @param string $name
     * @param array $options The following options keys are supported
     *  - size: default: 2048. Key sizes e.g 1024,2048,3072,4096
     *  - passphrase: An optional passphrase to use for the private key
     *  - algo:  default: sha512. digest algo. see openssl_get_md_methods()
     *  - expires: a strtotime compatible string on when the key can be used until
     *  - meta: an array of additional meta data which will be added
    * @return bool
    */
    public function create(string $name, array $options = []): bool
    {
        $keyPair = (new AsymmetricEncryption())->generateKeyPair($options);

        $tmpFile = sys_get_temp_dir() . '/' . uniqid() .'.tmp';
        $keyPair->export($tmpFile, true);
        $this->import($name, $tmpFile, $options);

        return file_exists($this->metaPath($name));
    }

    /**
     * Checks if a Key exists in the KeyChain
     *
     * @param string $name
     * @return boolean
     */
    public function exists(string $name): bool
    {
        return file_exists($this->metaPath($name));
    }

    /**
     * Imports an item into the KeyChain
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
        $keyPair = $this->toArray(trim($keyData)); // remove lineendings

        $data = [
            'id' => $this->keyId($name),
            'name' => $name,
            'privateKey' => $keyPair['private'],
            'publicKey' => $keyPair['public'],
            'fingerprint' => (new AsymmetricEncryption)->fingerprint($keyPair['public']),
            'expires' => $options['expires'] ? date('Y-m-d H:i:s', strtotime($options['expires'])) : null,
            'type' => empty($keyPair['private']) ? 'public-key' : 'key-pair',
            'comment' => $options['comment'],
            'created' => date('Y-m-d H:i:s')
        ];

        return (bool) file_put_contents(
            $this->metaPath($name),
            json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)
        );
    }

    /**
     * Gets the meta data for a key
     *
     * @param string $name name of key, e.g. username, email, UUID etc
     * @return \Encryption\Struct\Key
     */
    public function get(string $name): Key
    {
        $metaPath = $this->metaPath($name);
 
        if (! file_exists($metaPath)) {
            throw new NotFoundException("{$name} not found");
        }
        $meta = json_decode(file_get_contents($metaPath), true);
    
        return new Key($meta);
    }

    /**
     * Returns a list of Key IDs in the KeyChain
     *
     * @return array
     */
    public function list(): array
    {
        $out = [];
        foreach (scandir($this->path) as $file) {
            if (pathinfo($file, PATHINFO_EXTENSION) === 'json') {
                $out[] = substr($file, 0, -5);
            }
        }

        return $out;
    }

    /**
     * Deletes a Key from the KeyChain
     *
     * @param string $name
     * @return boolean
     */
    public function delete(string $name): bool
    {
        $metaPath = $this->metaPath($name);

        if (! file_exists($metaPath)) {
            throw new NotFoundException("Key for {$name} not found");
        }

        return unlink($metaPath);
    }

    /**
     * @param string $id
     * @return string
     */
    private function metaPath(string $id): string
    {
        return sprintf('%s/%s.json', $this->path, $id);
    }

    /**
     * Converts Key or Key pair to an array
     * @link https://blog.programster.org/key-file-formats
     *
     * @param string $secretPublicKey
     * @return void
     */
    protected function toArray(string $string)
    {
        if (! preg_match('/^-----BEGIN (.*) KEY-----$/m', $string)) {
            throw new InvalidArgumentException('Invalid Key');
        }
        $position = strpos($string, "-----\n-----");
        $publicKey = $string;
        $privateKey = null;

        if ($position) {
            $privateKey = substr($string, 0, $position + 5);
            $publicKey = substr($string, $position + 6);
        }

        return [
            'private' => $privateKey,
            'public' => $publicKey
        ];
    }
}
