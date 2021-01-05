<?php
/**
 * Encryption
 * Copyright 2020-2021 Jamiel Sharief.
 *
 * Licensed under The MIT License
 * The above copyright notice and this permission notice shall be included in all copies or substantial
 * portions of the Software.
 *
 * @copyright   Copyright (c) Jamiel Sharief
 * @license     https://opensource.org/licenses/mit-license.php MIT License
 */
declare(strict_types = 1);
namespace Encryption\Test;

use Encryption\PublicKey;
use Encryption\PrivateKey;
use Encryption\Exception\NotFoundException;
use Encryption\Exception\EncryptionException;

class PublicKeyTest extends \PHPUnit\Framework\TestCase
{
    public function testLoadException()
    {
        $this->expectException(NotFoundException::class);
        PublicKey::load('/path/to/somewhere/publicKey');
    }

    public function testInvalidKeyException()
    {
        $this->expectException(EncryptionException::class);
        PublicKey::load(__DIR__ .'/fixture/privateKey');
    }

    public function testDecryptFailure()
    {
        $publicKey = PublicKey::load(__DIR__ .'/fixture/publicKey');
        $this->expectException(EncryptionException::class);
        $publicKey->decrypt('foo');
    }

    public function testEncrypt()
    {
        $original = 'This is a test';
        $privateKey = PrivateKey::load(__DIR__ .'/fixture/privateKey');
        $publicKey = PublicKey::load(__DIR__ .'/fixture/publicKey');

        $encrypted = $publicKey->encrypt($original, ['addBoundaries' => true]);
        $this->assertStringContainsString('-----BEGIN ENCRYPTED DATA-----', $encrypted);
        $this->assertEquals($original, $privateKey->decrypt($encrypted));

        $this->assertStringNotContainsString('-----BEGIN ENCRYPTED DATA-----', $publicKey->encrypt($original, ['addBoundaries' => false]));
    }

    public function testDecrypt()
    {
        $original = 'This is a test';
        $privateKey = PrivateKey::load(__DIR__ .'/fixture/privateKey');
        $publicKey = PublicKey::load(__DIR__ .'/fixture/publicKey');

        $encrypted = $privateKey->encrypt($original, ['addBoundaries' => true]);
        $this->assertStringContainsString('-----BEGIN ENCRYPTED DATA-----', $encrypted);
        $this->assertEquals($original, $publicKey->decrypt($encrypted));
    }

    public function testFingerprint()
    {
        $publicKey = PublicKey::load(__DIR__ .'/fixture/publicKey');
        $this->assertEquals('2146 BD89 4696 A895 7416 4EAB 8A45 60A1 A7DC C83E', $publicKey->fingerprint());
    }

    public function testVerify()
    {
        $privateKey = PrivateKey::load(__DIR__ .'/fixture/privateKey');
        $publicKey = PublicKey::load(__DIR__ .'/fixture/publicKey');
        $signature = $privateKey->sign('foo', ['addBoundaries' => true]);
       
        $this->assertTrue($publicKey->verify('foo', $signature));
        $this->assertFalse($publicKey->verify('foo', str_replace('e539', 'e530', $signature)));
    }

    public function testToString()
    {
        $privateKey = PrivateKey::load(__DIR__ .'/fixture/privateKey');
        $publicKey = PublicKey::load(__DIR__ .'/fixture/publicKey');

        $this->assertEquals((string) $privateKey->extractPublicKey(), $publicKey->toString());
        $this->assertEquals((string) $privateKey->extractPublicKey(), (string) $publicKey);
    }

    public function testEncryptTooBig()
    {
        $text = file_get_contents(__DIR__ .'/fixture/large.txt');
        $publicKey = PublicKey::load(__DIR__ .'/fixture/publicKey');
        $this->expectException(EncryptionException::class);
        $publicKey->encrypt($text);
    }
}
