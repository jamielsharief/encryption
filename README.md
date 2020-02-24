# Encryption

This library supports both Asymmetric (using key pairs) and Symmetric (single key) encryption. 

## Asymmetric Encryption

### Generating a Public/Private Key Pair

To generate a public/private key pair

```php
$crypto = new AsymmetricEncryption();
$keyPair = $crypto->generateKeyPair();

$publicKey = $keyPair->public(); // this is used to encrypt data
$privateKey = $keyPair->private(); // this is to decrypt data
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


