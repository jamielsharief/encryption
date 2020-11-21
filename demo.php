<?php

use Encryption\Keychain;
use Encryption\PublicKey;
use Encryption\PrivateKey;

require __DIR__ . '/vendor/autoload.php';

$path = __DIR__ . '/demo';
@mkdir($path);
$keyChain = new Keychain($path);

$keyChain->create('demo@example.com');

echo "\nKeys in key chain:\n";
print_r($keyChain->list());

echo "\nKey generated:\n";
$document = $keyChain->get('demo@example.com');
print_r($document);

echo "\nEncrypted text:\n";
$publicKey = new PublicKey($document->publicKey);
$privateKey = new PrivateKey($document->privateKey);

$encrypted = $publicKey->encrypt('foo');
echo $encrypted . PHP_EOL;

echo "\nDecrypted text:\n";
echo $privateKey->decrypt($encrypted);
