# Encryption

![license](https://img.shields.io/badge/license-MIT-brightGreen.svg)
[![Build Status](https://travis-ci.com/jamielsharief/encryption.svg?branch=master)](https://travis-ci.com/jamielsharief/encryption)
[![Coverage Status](https://coveralls.io/repos/github/jamielsharief/encryption/badge.svg?branch=master)](https://coveralls.io/github/jamielsharief/encryption?branch=master)

This library supports both asymmetric (using key pairs) and symmetric (single key) encryption. There is also a Hybrid encryption which uses both asymmetric and symmetric. Both encrypted data and signatures are returned as a `Base64` encoded string.

## Asymmetric Encryption

### Generating Keys

To generate a key pair

```php
use Encryption\KeyPair;
$keyPair = KeyPair::generate();

$publicKey = $keyPair->publicKey(); // this is used to encrypt data
$privateKey = $keyPair->privateKey(); // this is to decrypt data
$string = $keyPair->toString(); // combines both key into a single string
```

Generate accepts the following options:

- size: default:4096 the size of the key
- passphrase: a password to encrypt the key with

## Working with Private Keys

To create a `PrivateKey` object using a private key string, pass this to the constructor

```php
use Encryption\PrivateKey;
$privateKey = new PrivateKey($string);
$privateKey = new PrivateKey($string, ['passphrase' => 'secret']));
```

To create a `PrivateKey` object by loading from a file

```php
use Encryption\PrivateKey;
$privateKey = PrivateKey::load($path);
$privateKey = PrivateKey::load($path, ['passphrase' => 'secret']);
```

Things you can do with the `PrivateKey` object

```php
$encrypted = $privateKey->encrypt($data);
$decrypted = $privateKey->decrypt($encrypted); // decrypts data encrypted by public key
$signature = $privateKey->sign($data);
$publicKey = $privateKey->extractPublicKey();
$bits = $privateKey->bits(); // 4096
echo $privateKey->toString();
```

You can also generate a private key using the static method `generate`, this will return a new `PrivateKey` object.

```php
$privateKey = PrivateKey::generate();
```


## Working with Public Keys

To create a `PublicKey` object using a public key string, pass this to the constructor

```php
use Encryption\PublicKey;
$publicKey = new PublicKey($string);
```

To create a `PublicKey` object by loading from a file

```php
use Encryption\PublicKey;
$publicKey = PublicKey::load($path);
```

Things you can do with the `PublicKey` object

```php
$encrypted = $publicKey->encrypt($data);
$decrypted = $publicKey->decrypt($encrypted); // decrypts data encrypted by private key
$signature = $publicKey->verify($data, $signature);
$fingerprint = $publicKey->fingerprint(); // D52A E482 CBE7 BB75 0148 3851 93A3 910A 0719 994D
$bits = $publicKey->bits(); // 4096
echo $publicKey->toString();
```


### Keychain

You can also manage keys with `Keychain`

```php
$keychain = new Keychain(__DIR__ . '/keys');
```

#### Creating keys and adding to the Key Chain

To create a private and public key pair and add this to the `Keychain`, you can pass an
email address, username, UUID or any other unique id.

```php
$keychain->create('jon@example.com');
```

You can also set an expiry date for the key

```php
$keychain->create('jon@example.com',[
    'expires' => '+ 1 year'
]);
```

#### Adding

> When you add a private key, the public key will be extracted and added to the same document.

To add a private or public key from a string.

```php
$keychain->add('user@example.com',(string) $privateKey);
```

#### Importing

> When you add a private key, the public key will be extracted and added to the same document.

To import an existing public key or private/public key pair

```php
$keychain->import('user-1979', __DIR__ .'/privateKey');
```

You can also set an expiry date for the key

```php
$keychain->import('user-1979', __DIR__ .'/publicKey',[
    'expires' => '+ 1 year'
]);
```

### Get

To get a key and data

```php
$key = $keychain->get('jon@example.com');
/*
DocumentStore\Document Object
(
    [id] => 784e148db03ac07ff34ae57c29b01549
    [name] => user@example.com
    [privateKey] => -----BEGIN PRIVATE KEY-----
MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEA0BaIweRiLW1Uunxw
NrPr9GaNWtnr+FbzsY8DNf894yI4n6q47s7yTPCFmHuIDzKaYx0xdS3L2XcY3HYg
ctPUNQIDAQABAkAMQ/fFrgeXc+VVpLYck1hqLI1SeJvvJHjy02I2EZh9RdDcBKi9
+MOuP+TzkVL0w1QAFgB8nPGblPjUB6FMhkwVAiEA9VmWwKxlTevev7XcOUYSOabv
qHeqab6aY8H1+o9+e3MCIQDZHuDTTizUW4frKhvtKiBkwAV4YdErVM9LNFC+TFTX
twIhAL8o/FJGf+/EVRtdoKZnOA//Rz8lbXtSbIxJNVPxtYSNAiBhI5CA2WPzKnRY
AUH3TLarfMG1x0W29j28Ls7FJQ98ZwIgH5Esr246hK1bSGO4R2Z6yFCcBfo1Sgib
bjupP+8HbUs=
-----END PRIVATE KEY-----
    [publicKey] => -----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANAWiMHkYi1tVLp8cDaz6/RmjVrZ6/hW
87GPAzX/PeMiOJ+quO7O8kzwhZh7iA8ymmMdMXUty9l3GNx2IHLT1DUCAwEAAQ==
-----END PUBLIC KEY-----

    [fingerprint] => E010 6888 BE78 1571 D35A D3CC 22C7 62D3 6025 E288
    [expires] => 2050-01-01 12:00:00
    [type] => key-pair
    [comment] => foo
    [created] => 2020-11-20 17:07:41
)
*/
```

### Delete

To delete a key and data

```php
$keychain->delete('jon@example.com');
```

### List

To get a list of keys

```php
$keychain->list();
```


## Symmetric Encryption

First you need to generate a key that must be 32 bits

```php
$crypto = new SymmetricEncryption();
$key = $crypto->generateKey(); // 3LSpUJL4s0HNLun4T1KcheGjrVtCjaQ7
```

To encrypt a string

```php
$crypto = new SymmetricEncryption();
$encrypted = $crypto->encrypt($text, $key);
```

To decrypt a string

```php
$crypto = new SymmetricEncryption();
$decrypted = $crypto->decrypt($text, $key);
```

## Hybrid Encryption

> This can only decrypt data encrypted with the Hybrid Encryption class

Hybrid encryption uses both asymmetric and symmetric encryption. With hybrid encryption there is no limit on message size.

```php
$publicKey = PublicKey::load($pathToPublicKey);
$privateKey = PrivateKey::load($pathToPrivateKey);

$crypto = new HybridEncryption();

$encrypted = $crypto->encrypt($data, $publicKey);
echo $crypto->decrypt($encrypted, $privateKey);
```

By default encrypted/signed data is wrapped in a ENCRYPTED DATA or SIGNATURE boundary, however this can be disabled when encrypting or signing data. For example

```text
-----BEGIN ENCRYPTED DATA-----
eGrjYfLFQI/gVWfpZeEA05q7Swb9gaKRalZnBZ788mGXiOhj1+f+a2RLJxDu24FE1HnFd70YcPAAdWme1Lu0yQ==
-----END ENCRYPTED DATA-----
```

Decryption and signature verification will remove boundaries automatically if they are found present in the data.