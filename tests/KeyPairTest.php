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

use Encryption\KeyPair;

class KeyPairTest extends \PHPUnit\Framework\TestCase
{
    public function testToString()
    {
        $publicKey = file_get_contents(__DIR__ . '/fixture/public.key');
        $privateKey = file_get_contents(__DIR__ . '/fixture/private.key');
        $keyPair = new KeyPair($privateKey, $publicKey);
    
        $this->assertSame($keyPair->privateKey() . PHP_EOL . $keyPair->publicKey(), (string) $keyPair);
    }
}
