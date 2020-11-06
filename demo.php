<?php

use Encryption\Keychain;
use Encryption\AsymmetricEncryption;

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
$crypto = new AsymmetricEncryption();
$encrypted = $crypto->encrypt('foo', $document['publicKey']);
echo $encrypted . PHP_EOL;

echo "\nDecrypted text:\n";
echo $crypto->decrypt($encrypted, $document['privateKey']);
