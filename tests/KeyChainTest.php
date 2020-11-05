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

use Encryption\KeyChain;
use Encryption\Struct\Key;
use Encryption\AsymmetricEncryption;
use Encryption\Exception\NotFoundException;

class KeyChainTest extends \PHPUnit\Framework\TestCase
{
    const USERNAME = 'user@example.com';

    public function testKeyId()
    {
        $this->assertEquals('1db7afcfec00120a8812a4c6a1a267c0', $this->keyChain()->keyId('foo'));
    }

    public function testCreate()
    {
        $this->assertTrue($this->keyChain()->create(self::USERNAME));
    }

    public function testGet()
    {
        $keyChain = $this->keyChain();
        
        $this->assertTrue($keyChain->create(self::USERNAME, [
            'meta' => ['foo' => 'bar'],
            'expires' => '2050-01-01 12:00:00'
        ]));
        $created = date('Y-m-d H:i:s');

        $key = $keyChain->get(self::USERNAME);
        $this->assertInstanceOf(Key::class, $key);

        $this->assertEquals('2050-01-01 12:00:00', $key->expires);
        $this->assertEquals('bar', $key->meta['foo']);
        $this->assertEquals($created, $key->created);
        $this->assertEquals((new AsymmetricEncryption())->fingerprint($key->publicKey), $key->fingerprint);
    }

    public function testExists()
    {
        $keyChain = $this->keyChain();
        $this->assertTrue($keyChain->create(self::USERNAME));
        $this->assertTrue($keyChain->exists(self::USERNAME));
        $this->assertFalse($keyChain->exists('you@yourdomain.com'));
    }

    public function testList()
    {
        $keyChain = $this->keyChain();
        $this->assertTrue($keyChain->create(self::USERNAME));
        $this->assertEquals([self::USERNAME], $keyChain->list());
    }

    public function testDelete()
    {
        $keyChain = $this->keyChain();
        $this->assertTrue($keyChain->create(self::USERNAME));
        $this->assertTrue($keyChain->delete(self::USERNAME));
        $this->expectException(NotFoundException::class);
        $this->assertFalse($keyChain->delete(self::USERNAME));
    }

    public function testImportPublicKeyOnly()
    {
        $crypto = new AsymmetricEncryption();
        $keyPair = $crypto->generateKeyPair();
        $tmpFile = sys_get_temp_dir() . '/' . uniqid();
        file_put_contents($tmpFile, $keyPair->publicKey());
        $keyChain = $this->keyChain();
        $this->assertTrue($keyChain->import(self::USERNAME, $tmpFile));
        $key = $keyChain->get(self::USERNAME);
        $this->assertEquals($keyPair->publicKey(), $key->publicKey);
    }

    public function testImportPublicOnly()
    {
        $crypto = new AsymmetricEncryption();
        $keyPair = $crypto->generateKeyPair();
        $tmpFile = sys_get_temp_dir() . '/' . uniqid();
        $keyPair->export($tmpFile, false);
        $keyChain = $this->keyChain();
        $this->assertTrue($keyChain->import(self::USERNAME, $tmpFile));
        $key = $keyChain->get(self::USERNAME);
        $this->assertEquals($keyPair->publicKey(), $key->publicKey);
        $this->assertNull($key->privateKey);
        $this->assertEquals('public-key', $key->type);
    }

    public function testImport()
    {
        $crypto = new AsymmetricEncryption();
        $keyPair = $crypto->generateKeyPair();
        $tmpFile = sys_get_temp_dir() . '/' . uniqid();
        $keyPair->export($tmpFile, true);
        $keyChain = $this->keyChain();
        $this->assertTrue($keyChain->import(self::USERNAME, $tmpFile));
        $key = $keyChain->get(self::USERNAME);
        $this->assertEquals($keyPair->publicKey(), $key->publicKey);
        $this->assertEquals($keyPair->privateKey(), $key->privateKey);
        $this->assertEquals('key-pair', $key->type);
    }

    private function keyChain()
    {
        $path = sys_get_temp_dir() . '/' . uniqid();
        mkdir($path);

        return new KeyChain($path);
    }
}
