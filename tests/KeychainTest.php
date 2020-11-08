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

use Encryption\Keychain;
use DocumentStore\Document;
use InvalidArgumentException;
use Encryption\AsymmetricEncryption;
use Encryption\Exception\NotFoundException;

class KeychainTest extends \PHPUnit\Framework\TestCase
{
    const USERNAME = 'user@example.com';

    public function testInvalidPath()
    {
        $this->expectException(InvalidArgumentException::class);
        new Keychain('/somewhere/outthere');
    }

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
            'comment' => 'foo',
            'expires' => '2050-01-01 12:00:00'
        ]));
        $created = date('Y-m-d H:i:s');

        $key = $keyChain->get(self::USERNAME);
        $this->assertInstanceOf(Document::class, $key);

        $this->assertEquals('2050-01-01 12:00:00', $key->expires);
        $this->assertEquals('foo', $key->comment);
        $this->assertEquals($created, $key->created);
        $this->assertEquals((new AsymmetricEncryption())->fingerprint($key->publicKey), $key->fingerprint);
    }

    public function testGetException()
    {
        $keyChain = $this->keyChain();
        $this->expectException(NotFoundException::class);
        $keyChain->get('foo');
    }

    public function testExists()
    {
        $keyChain = $this->keyChain();
        $this->assertTrue($keyChain->create(self::USERNAME));
        $this->assertTrue($keyChain->has(self::USERNAME));
        $this->assertFalse($keyChain->has('you@yourdomain.com'));
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
        file_put_contents($tmpFile, $keyPair->publicKey());

        $keyChain = $this->keyChain();
        $this->assertTrue($keyChain->import(self::USERNAME, $tmpFile));
        $key = $keyChain->get(self::USERNAME);
        $this->assertEquals($keyPair->publicKey(), $key->publicKey);
        $this->assertNull($key->privateKey);
        $this->assertEquals('public-key', $key->type);
    }

    public function testImportPrivateOnly()
    {
        $keyChain = $this->keyChain();
        $this->assertTrue($keyChain->import(self::USERNAME, __DIR__ . '/fixture/private.key'));
        $key = $keyChain->get(self::USERNAME);

        $this->assertStringContainsString('---BEGIN PRIVATE KEY', $key->privateKey);
        $this->assertStringContainsString('---BEGIN PUBLIC KEY', $key->publicKey);
        $this->assertEquals('key-pair', $key->type);
    }

    public function testImport()
    {
        $crypto = new AsymmetricEncryption();
        $keyPair = $crypto->generateKeyPair();
        $tmpFile = sys_get_temp_dir() . '/' . uniqid();
        file_put_contents($tmpFile, (string) $keyPair);
        
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

        return new Keychain($path);
    }
}
