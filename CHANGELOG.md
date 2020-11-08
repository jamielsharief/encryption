# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] 

### Removed

- Removed KeyPair export as this was confusing

### Changed

- Changed KeyPair construct argument order - Breaking change if have used this class.

### Fixed

- Fixed Fingerprint which generated incorrect fingerprint if user passed either a private key or both a private and public key

## [0.3.0] - 2020-11-07

### Added

- Added AsymmetricEncryption::generatePrivateKey
- Added AsymmetricEncryption::extractPublicKey
- Added KeyPair::__toString

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