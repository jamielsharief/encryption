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

use Encryption\PublicKey;
use Encryption\PrivateKey;
use Encryption\Exception\NotFoundException;
use Encryption\Exception\EncryptionException;

class PrivateKeyTest extends \PHPUnit\Framework\TestCase
{
    public function testLoadException()
    {
        $this->expectException(NotFoundException::class);
        PrivateKey::load('/path/to/somewhere/privateKey');
    }

    public function testInvalidKeyException()
    {
        $this->expectException(EncryptionException::class);
        PrivateKey::load(__DIR__ .'/fixture/publicKey');
    }

    public function testEncrypt()
    {
        $original = 'This is a test';
        $privateKey = PrivateKey::load(__DIR__ .'/fixture/privateKey');
        $publicKey = PublicKey::load(__DIR__ .'/fixture/publicKey');

        $encrypted = $privateKey->encrypt($original, ['addBoundaries' => true]);
   
        $this->assertStringContainsString('-----BEGIN ENCRYPTED DATA-----', $encrypted);
        $this->assertEquals($original, $publicKey->decrypt($encrypted));

        $this->assertStringNotContainsString('-----BEGIN ENCRYPTED DATA-----', $publicKey->encrypt($original, ['addBoundaries' => false]));
    }

    public function testDecrypt()
    {
        $original = 'This is a test';
        $privateKey = PrivateKey::load(__DIR__ .'/fixture/privateKey');
        $publicKey = PublicKey::load(__DIR__ .'/fixture/publicKey');

        $encrypted = $publicKey->encrypt($original, ['addBoundaries' => true]);
        $this->assertStringContainsString('-----BEGIN ENCRYPTED DATA-----', $encrypted);
        $this->assertEquals($original, $privateKey->decrypt($encrypted));
    }

    public function testDecryptFailure()
    {
        $privateKey = PrivateKey::load(__DIR__ .'/fixture/privateKey');
        $this->expectException(EncryptionException::class);
        $privateKey->decrypt('foo');
    }

    public function testSign()
    {
        $privateKey = PrivateKey::load(__DIR__ .'/fixture/privateKey');
        $this->assertStringContainsString('-----BEGIN SIGNATURE-----', $privateKey->sign('This is a test', ['addBoundaries' => true]));
    }

    /**
     * This must be the encrypted version not the unencrypted version which openssl_pkey_get_private
     * will create when passing a passphrase
     */
    public function testToString()
    {
        $privateKey = PrivateKey::generate(['size' => 512,'passphrase' => 'foo']);
     
        $this->assertStringContainsString('-----BEGIN ENCRYPTED PRIVATE KEY-----', $privateKey->toString());
        $this->assertStringContainsString('-----BEGIN ENCRYPTED PRIVATE KEY-----', (string) $privateKey->toString());
    }

    public function testExtractPublicKey()
    {
        $privateKey = PrivateKey::load(__DIR__ .'/fixture/privateKey');
        $publicKey = PublicKey::load(__DIR__ .'/fixture/publicKey');

        $this->assertEquals((string) $publicKey, (string) $privateKey->extractPublicKey());
    }

    public function testEncryptTooBig()
    {
        $text = file_get_contents(__DIR__ .'/fixture/large.txt');
        $privateKey = PrivateKey::load(__DIR__ .'/fixture/privateKey');
        $this->expectException(EncryptionException::class);
        $privateKey->encrypt($text);
    }
}
