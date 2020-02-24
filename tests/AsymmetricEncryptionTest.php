<?php
/**
 * OriginPHP Framework
 * Copyright 2018 - 2020 Jamiel Sharief.
 *
 * Licensed under The MIT License
 * The above copyright notice and this permission notice shall be included in all copies or substantial
 * portions of the Software.
 *
 * @copyright   Copyright (c) Jamiel Sharief
 * @link        https://www.originphp.com
 * @license     https://opensource.org/licenses/mit-license.php MIT License
 */

namespace Origin\Test\Security;

use ErrorException;
use Encryption\KeyPair;
use Encryption\AsymmetricEncryption;

class AsymmetricEncryptionTest extends \PHPUnit\Framework\TestCase
{
    public function testGenerateKeyPair()
    {
        $crypto = new AsymmetricEncryption();
        $keyPair = $crypto->generateKeyPair(['size' => 2048,'algo' => 'sha256']);
        $this->assertStringContainsString('-----BEGIN PRIVATE KEY-----', $keyPair->private());
        $this->assertStringContainsString('-----BEGIN PUBLIC KEY-----', $keyPair->public());
    }

    public function testSign()
    {
        $crypto = new AsymmetricEncryption();
        $keyPair = $crypto->generateKeyPair(['size' => 2048,'algo' => 'sha256']);
        $string = 'Every cloud has a silver lining';
        $signature = $crypto->sign($string, $keyPair->private());

        $this->assertTrue($crypto->verify($string, $signature, $keyPair->public()));
        $this->assertFalse($crypto->verify($string.'f', $signature, $keyPair->public()));
    }

    public function testGenerateKeyPairWithPassphrase()
    {
        $crypto = new AsymmetricEncryption();
        $keyPair = $crypto->generateKeyPair(['passphrase' => 'foo']);
        $this->assertStringContainsString('-----BEGIN ENCRYPTED PRIVATE KEY-----', $keyPair->private());
        $this->assertStringContainsString('-----BEGIN PUBLIC KEY-----', $keyPair->public());

        //file_put_contents('private-pass.key', $keyPair->private());
        //file_put_contents('public-pass.key', $keyPair->public());
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

    public function testEncryptDecrypt()
    {
        $crypto = new AsymmetricEncryption();
        
        $publicKey = file_get_contents(__DIR__ . '/fixture/public.key');
        $encrypted = $crypto->encrypt('foo', $publicKey);
        $this->assertStringContainsString('-----BEGIN ENCRYPTED DATA-----', $encrypted);

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
}
