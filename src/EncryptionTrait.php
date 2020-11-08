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

trait EncryptionTrait
{
    /**
         * Parses a key or key pair into an array, different key types have different boundaries
         * e.g. BEGIN PRIVATE KEY, BEGIN RSA PRIVATE KEY
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
