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

use ErrorException;
use Encryption\KeyPair;
use Encryption\AsymmetricEncryption;
use Encryption\Exception\EncryptionException;

class AsymmetricEncryptionTest extends \PHPUnit\Framework\TestCase
{
    public function testGenerateKeyPair()
    {
        $crypto = new AsymmetricEncryption();
        $keyPair = $crypto->generateKeyPair(['size' => 2048,'algo' => 'sha256']);
        $this->assertStringContainsString('-----BEGIN PRIVATE KEY-----', $keyPair->privateKey());
        $this->assertStringContainsString('-----BEGIN PUBLIC KEY-----', $keyPair->publicKey());
    }

    public function testSign()
    {
        $crypto = new AsymmetricEncryption();
        $keyPair = $crypto->generateKeyPair(['size' => 2048,'algo' => 'sha256']);
        $string = 'Every cloud has a silver lining';
        $signature = $crypto->sign($string, $keyPair->privateKey());
        
        $this->assertTrue($crypto->verify($string, $signature, $keyPair->publicKey()));
        $this->assertFalse($crypto->verify($string.'f', $signature, $keyPair->publicKey()));
    }

    public function testSignWithPassphrase()
    {
        $crypto = new AsymmetricEncryption();
        $keyPair = $crypto->generateKeyPair(['size' => 1024,'passphrase' => 'secret']);
        $string = 'Every cloud has a silver lining';
        $signature = $crypto->sign($string, $keyPair->privateKey(), 'secret');

        $this->assertTrue($crypto->verify($string, $signature, $keyPair->publicKey()));
        $this->assertFalse($crypto->verify($string.'f', $signature, $keyPair->publicKey()));
    }

    public function testSignWithIncorrectPassphrase()
    {
        $this->expectException(EncryptionException::class);

        $crypto = new AsymmetricEncryption();
        $keyPair = $crypto->generateKeyPair(['size' => 1024,'passphrase' => 'secret']);
        $string = 'Every cloud has a silver lining';
        $signature = $crypto->sign($string, $keyPair->privateKey(), 'foo');

        $this->assertFalse($crypto->verify($string, $signature, $keyPair->publicKey()));
    }

    public function testGenerateKeyPairWithPassphrase()
    {
        $crypto = new AsymmetricEncryption();
        $keyPair = $crypto->generateKeyPair(['passphrase' => 'foo']);
        $this->assertStringContainsString('-----BEGIN ENCRYPTED PRIVATE KEY-----', $keyPair->privateKey());
        $this->assertStringContainsString('-----BEGIN PUBLIC KEY-----', $keyPair->publicKey());

        //file_put_contents('private-pass.key', $keyPair->privateKey());
        //file_put_contents('public-pass.key', $keyPair->publicKey());
    }

    /**
     * Testing no issues when passing params
     *
     * @return void
     */
    public function testGenerateKeyPairBits()
    {
        $this->expectError(ErrorException::class);
        $crypto = new AsymmetricEncryption();
        $keyPair = $crypto->generateKeyPair(['size' => -1]);
    }

    /**
     * Not sure how to test this, as no errors come up if you put a incorrect
     * digest
     *
     * @return void
     */
    public function testGenerateKeyPairAlgo()
    {
        $crypto = new AsymmetricEncryption();
        $keyPair = $crypto->generateKeyPair(['algo' => 'sha256']);
        $this->assertInstanceOf(KeyPair::class, $keyPair);
    }

    public function testFingerprint()
    {
        $publicKey = file_get_contents(__DIR__ . '/fixture/public.key');
        $privateKey = file_get_contents(__DIR__ . '/fixture/private.key');
        $keyPair = new KeyPair($privateKey, $publicKey);
        $this->assertEquals('9C94 5F9A 7BBB 171D D988 3816 15B3 4199 8367 CFA3', $keyPair->fingerprint());
        $this->assertEquals('9C94 5F9A 7BBB 171D D988 3816 15B3 4199 8367 CFA3', (new AsymmetricEncryption())->fingerprint($publicKey));
    }

    public function testEncryptDecrypt()
    {
        $crypto = new AsymmetricEncryption();
        
        $publicKey = file_get_contents(__DIR__ . '/fixture/public.key');
        $encrypted = $crypto->encrypt('foo', $publicKey);
        $this->assertStringContainsString('-----BEGIN ENCRYPTED DATA-----', $encrypted);

        $privateKey = file_get_contents(__DIR__ . '/fixture/private.key');
       
        $this->assertEquals('foo', $crypto->decrypt($encrypted, $privateKey));

        // test failure
        $privateKey = str_replace('YRP', 'foo', $privateKey);
        $this->expectException(EncryptionException::class);
        $crypto->decrypt('foo', $privateKey);
    }

    public function testEncryptDecryptNoBoundaries()
    {
        $crypto = new AsymmetricEncryption();
        
        $publicKey = file_get_contents(__DIR__ . '/fixture/public.key');
        $encrypted = $crypto->encrypt('foo', $publicKey, false);
        $this->assertStringNotContainsString('-----BEGIN ENCRYPTED DATA-----', $encrypted);

        $privateKey = file_get_contents(__DIR__ . '/fixture/private.key');
       
        $this->assertEquals('foo', $crypto->decrypt($encrypted, $privateKey));
    }

    public function testEncryptPassphrase()
    {
        $crypto = new AsymmetricEncryption();
        
        $publicKey = file_get_contents(__DIR__ . '/fixture/public-pass.key');
        $encrypted = $crypto->encrypt('foo', $publicKey);
        $this->assertStringContainsString('-----BEGIN ENCRYPTED DATA-----', $encrypted);

        $privateKey = file_get_contents(__DIR__ . '/fixture/private-pass.key');
        $this->assertEquals('foo', $crypto->decrypt($encrypted, $privateKey, 'foo'));
    }

    public function testEncryptInvalidPassphrase()
    {
        $this->expectException(EncryptionException::class);
        $crypto = new AsymmetricEncryption();
        
        $publicKey = file_get_contents(__DIR__ . '/fixture/public-pass.key');
        $encrypted = $crypto->encrypt('foo', $publicKey);
        $this->assertStringContainsString('-----BEGIN ENCRYPTED DATA-----', $encrypted);

        $privateKey = file_get_contents(__DIR__ . '/fixture/private-pass.key');
        $crypto->decrypt($encrypted, $privateKey, 'bar');
    }
}
