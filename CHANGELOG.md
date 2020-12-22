# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


Upcoming 2.0 changes

- [ ] Toggle base64 encoding (constructor level) in Asymmetric/Symmetric
- [ ] Removed Deprecated Features
- [ ] Make min 7.4
- [ ] Adjust Hybrid to toggle base64 instead of decode

## [1.2.0] - 2020-12-22

### Added

- Added Hybrid Encryption
- Added PrivateKey::bits 
- Added PublicKey::bits
- Add check data length on encryption against key size limit

### Changed

- Changed boundaries are no longer added by default in Asymmetric Encryption

## [1.1.0] - 2020-11-21

### Changed

- Changed Keychain::create default key size to 4096

### Added

- Added Keychain::add
- Added KeyPair::generate
- Added PrivateKey object
- Added PublicKey object

### Security

- The AsymmetricEncrytion wrapper does not use OEP Padding, migrate to use the PrivateKey and PublicKey objects

## [1.0.0] - 2020-11-08

### Added

- Added AsymmetricEncryption::generatePrivateKey
- Added AsymmetricEncryption::extractPublicKey
- Added KeyPair::toString

### Removed

- Removed KeyPair export as this was confusing

### Changed

- Changed KeyPair construct argument order - Breaking change if have used this class.

### Fixed

- Fixed Fingerprint which generated incorrect fingerprint if user passed either a private key or both a private and public key

## [0.2.1] - 2020-11-06

### Changed

- Renamed the KeyChain to Keychain

## [0.2.0] - 2020-11-05

### Changed

- Changed key pair export order so that the private key is first
- Renamed KeyPair::public to publicKey
- Renamed KeyPair::private to privateKey

## Added

- Added KeyChain