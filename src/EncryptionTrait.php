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

trait EncryptionTrait
{
    private $boundaryPattern = "#-----\r?\n(.*)\r?\n-----#s";

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
     *
     * @param string $data
     * @return string
     */
    protected function removeBoundaries(string $data): string
    {
        preg_match($this->boundaryPattern, $data, $matches);
        if ($matches) {
            $data = $matches[1];
        }

        return $data;
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
}
