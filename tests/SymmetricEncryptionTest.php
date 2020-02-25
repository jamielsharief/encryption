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
namespace Encryption\Test;

use Encryption\SymmetricEncryption;
use Encryption\Exception\EncryptionException;

class SymmetricEncryptionTest extends \PHPUnit\Framework\TestCase
{
    public function testGenerateKey()
    {
        $crypto = new SymmetricEncryption();
        $key = $crypto->generateKey();

        $this->assertStringMatchesFormat('%x', $key);
        $this->assertEquals(32, strlen($key));
    }

    public function testEncryptDecrypt()
    {
        $text = 'another day another doug';
        $crypto = new SymmetricEncryption();
        $key = $crypto->generateKey();
        $encrypted = $crypto->encrypt($text, $key);
        $this->assertNotEquals($encrypted, $text);
        $decrypted = $crypto->decrypt($encrypted, $key);
        $this->assertEquals($text, $decrypted);
    }

    public function testEncryptDecryptInvalid()
    {
        $this->expectException(EncryptionException::class);
        $text = 'another day another doug';
        $crypto = new SymmetricEncryption();
        $key = $crypto->generateKey();
       
        $encrypted = $crypto->encrypt($text, $key);
     
        $decrypted = $crypto->decrypt($encrypted, 'd0b5e608b9223b4564d3c075c1b97906');
    }
}
