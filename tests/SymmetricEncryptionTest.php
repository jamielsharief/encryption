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

use Encryption\SymmetricEncryption;

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
        print $encrypted;
    }
}
