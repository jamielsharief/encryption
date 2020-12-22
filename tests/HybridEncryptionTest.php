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
use Encryption\HybridEncryption;

class HybridEncryptionTest extends \PHPUnit\Framework\TestCase
{
    public function testEncryptWithPublicKey()
    {
        $text = file_get_contents(__DIR__ .'/fixture/large.txt');
        $privateKey = PrivateKey::load(__DIR__ .'/fixture/privateKey');
        $publicKey = PublicKey::load(__DIR__ .'/fixture/publicKey');

        $crypto = new HybridEncryption();
        $encrypted = $crypto->encrypt($text, $publicKey);
        $this->assertEquals($text, $crypto->decrypt($encrypted, $privateKey));
    }

    public function testEncryptWithPrivateKey()
    {
        $text = file_get_contents(__DIR__ .'/fixture/large.txt');
        $privateKey = PrivateKey::load(__DIR__ .'/fixture/privateKey');
        $publicKey = PublicKey::load(__DIR__ .'/fixture/publicKey');

        $crypto = new HybridEncryption();
        $encrypted = $crypto->encrypt($text, $privateKey);
        $this->assertEquals($text, $crypto->decrypt($encrypted, $publicKey));
    }
}
