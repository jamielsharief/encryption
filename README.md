# Encryption

This library supports both Asymmetric (using key pairs) and Symmetric (single key) encryption. 

## Asymmetric Encryption


### Encryption

First you need to generate a key pair (public and private key).

```php
$crypto = new AsymmetricEncryption();
$keyPair = $crypto->generateKeyPair();

$publicKey = $keyPair->public(); // this is used to encrypt data
$privateKey = $keyPair->private(); // this is to decrypt data
```

To encrypt a string

```php
$crypto = new AsymmetricEncryption();
$encrypted = $crypto->encrypt($text,$publicKey);
```

To decrypt a string

```php
$crypto = new AsymmetricEncryption();
$decrypted = $crypto->decrypt($encrypted,$privateKey);
```

### Encryption with a passphrase

If you wish to password protect the decryption process, when you generate the key
supply a password.

```php
$crypto = new AsymmetricEncryption();
$keyPair = $crypto->generateKeyPair(['password'=>'secret']);
```

To encrypt a string with a passphrase

```php
$crypto = new AsymmetricEncryption();
$encrypted = $crypto->encrypt($text,$publicKey,'secret');
```

To decrypt a string with a passphrase

```php
$crypto = new AsymmetricEncryption();
$decrypted = $crypto->decrypt($encrypted,$privateKey,'secret');
```

## Symmetric Encryption

First you need to generate a key that must be 32 bits.

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


