# Encryption

![license](https://img.shields.io/badge/license-MIT-brightGreen.svg)
[![Build Status](https://travis-ci.org/jamielsharief/encryption.svg?branch=master)](https://travis-ci.org/jamielsharief/encryption)
[![Coverage Status](https://coveralls.io/repos/github/jamielsharief/encryption/badge.svg?branch=master)](https://coveralls.io/github/jamielsharief/encryption?branch=master)

This library supports both Asymmetric (using key pairs) and Symmetric (single key) encryption. 

## Asymmetric Encryption

### Generating a Public/Private Key Pair

To generate a public/private key pair

```php
use Encryption\AsymmetricEncryption;

$crypto = new AsymmetricEncryption();
$keyPair = $crypto->generateKeyPair();

$publicKey = $keyPair->publicKey(); // this is used to encrypt data
$privateKey = $keyPair->privateKey(); // this is to decrypt data
```

The default key size is 2048, however you can change this when generating a key pair.

```php
$crypto = new AsymmetricEncryption();
$keyPair = $crypto->generateKeyPair(['size'=>4096]);
```

To encrypt your private key with a passphrase

```php
$crypto = new AsymmetricEncryption();
$keyPair = $crypto->generateKeyPair(['passphrase'=>'d0b5e608b9223b4564d3c075c1b97906']);
```

#### Fingerprint

To get the public key fingerprint when generating a key pair

```php
$crypto = new AsymmetricEncryption();
$keyPair = $crypto->generateKeyPair();
$fingerprint = $keypair->fingerprint();   // 1087 BE17 0C58 B41D 5913 8C8E CFE7 B696 6111 4AAB
```

To generate the fingerprint of any public key 

```php
$fingerprint = (new AsymmetricEncryption())->fingerprint($publicKey);
```

#### Exporting Keys

To export your public key from the key pair

```php
$keypair->export('/Users/james/code/public/james.pub');
```

To export both the public and private key from the key pair

```php
$keypair->export('/Users/james/code/public/james.ppk' , true);
```

### Encrypting

To encrypt a string

```php
$crypto = new AsymmetricEncryption();
$encrypted = $crypto->encrypt($text,$publicKey);
```

### Encrypting with a passphrase

If you created your keypair with a passphrase then to encrypt using this 

```php
$crypto = new AsymmetricEncryption();
$encrypted = $crypto->encrypt($text,$publicKey,'d0b5e608b9223b4564d3c075c1b97906');
```

### Decrypting

To decrypt a string

```php
$crypto = new AsymmetricEncryption();
$decrypted = $crypto->decrypt($encrypted,$privateKey);
```

### Decrypting with a Passphrase

To decrypt a string with a passphrase

```php
$crypto = new AsymmetricEncryption();
$decrypted = $crypto->decrypt($encrypted,$privateKey,'d0b5e608b9223b4564d3c075c1b97906');
```

### Signing and verifying

To sign a string, this will return a signature

```php
$signed = (new AsymmetricEncryption())-sign($data, $privateKey);
```

If your private key is encrypted with a passphrase

```php
$signed = (new AsymmetricEncryption())-sign($data, $privateKey,'d0b5e608b9223b4564d3c075c1b97906');
```

To verify the signature

```php
$bool = (new AsymmetricEncryption())-verify($data, $signature, $publicKey);
```

### KeyChain

You can also manage keys with `KeyChain`

```php
$keyChain = new KeyChain(__DIR__ . '/keys');
```

#### Creating keys and adding to the Key Chain

To create a private and public key pair and add this to the `KeyChain`, you can pass an
email address, username, UUID or any other unique id.

```php
$keyChain->create('jon@example.com');
```

You can also set an expiry date for the key

```php
$keyChain->create('jon@example.com',[
    'expires' => '+ 1 year'
]);
```

#### Importing

To import an existing public key or private/public key pair

```php
$keyChain->import('user-1979', __DIR__ .'/private.key');
```

You can also set an expiry date for the key

```php
$keyChain->import('user-1979',__DIR__ .'/public.key',[
    'expires' => '+ 1 year'
]);
```

### Get

To get a key and data

```php
$key = $keyChain->get('jon@example.com');
```

### Delete

To delete a key and data

```php
$keyChain->delete('jon@example.com');
```

### List

To get a list of keys

```php
$keyChain->list();
```


## Symmetric Encryption

First you need to generate a key that must be 32 bits, for example `46d3e5d2cdd5c1c5a677a4d91af3e3b7`

```php
$crypto = new SymmetricEncryption();
$key = $crypto->generateKey(); // this is used to encrypt/decrypt
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


