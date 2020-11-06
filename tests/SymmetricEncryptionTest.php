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

use InvalidArgumentException;
use Encryption\SymmetricEncryption;
use Encryption\Exception\EncryptionException;

class MockSymmetricEncryption extends SymmetricEncryption
{
    public function callCompare(string $a, $b)
    {
        return $this->compare($a, $b);
    }
}
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
        $text = 'another day another doug';
        $crypto = new SymmetricEncryption();
        $key = $crypto->generateKey();
       
        $encrypted = $crypto->encrypt($text, $key);

        $this->expectException(EncryptionException::class);
        $decrypted = $crypto->decrypt($encrypted, 'd0b5e608b9223b4564d3c075c1b97906');
    }

    public function testEncryptInvalidKey()
    {
        $crypto = new SymmetricEncryption();
        $this->expectException(InvalidArgumentException::class);
        $crypto->encrypt('foo', '123');
    }

    public function testDecryptInvalidKey()
    {
        $crypto = new SymmetricEncryption();
        $this->expectException(InvalidArgumentException::class);
        $crypto->decrypt('foo', '123');
    }

    public function testCompare()
    {
        $crypto = new MockSymmetricEncryption();
        $this->assertTrue($crypto->callCompare('a', 'a'));
        $this->assertFalse($crypto->callCompare('a', null));
    }
}
