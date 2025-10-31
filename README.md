# TLS-Crypto-Hash

[English](README.md) | [中文](README.zh-CN.md)

[![Latest Version](https://img.shields.io/packagist/v/tourze/tls-crypto-hash.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-crypto-hash)
[![PHP Version](https://img.shields.io/badge/php-%3E%3D8.1-brightgreen.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-crypto-hash)
[![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](LICENSE)
[![Coverage](https://img.shields.io/badge/coverage-%3E90%25-brightgreen.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-crypto-hash)
[![Total Downloads](https://img.shields.io/packagist/dt/tourze/tls-crypto-hash.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-crypto-hash)

A comprehensive PHP library providing cryptographic hash functions, 
message authentication codes (MAC), and key derivation functions (KDF) 
designed for TLS protocol implementations.

## Table of Contents

- [Installation](#installation)
- [Requirements](#requirements)
- [Features](#features)
- [Usage](#usage)
  - [Hash Functions](#hash-functions)
  - [Message Authentication Code (MAC)](#message-authentication-code-mac)
  - [Key Derivation Function (KDF)](#key-derivation-function-kdf)
  - [PBKDF2 for Password Hashing](#pbkdf2-for-password-hashing)
  - [Advanced MAC Examples](#advanced-mac-examples)
- [Advanced Usage](#advanced-usage)
  - [TLS 1.2 and 1.3 Implementations](#tls-12-and-13-implementations)
  - [Custom Configuration](#custom-configuration)
  - [Performance Optimization](#performance-optimization)
- [Supported Algorithms](#supported-algorithms)
  - [Hash Functions](#hash-functions)
  - [MAC Algorithms](#mac-algorithms)
  - [KDF Algorithms](#kdf-algorithms)
- [Security Considerations](#security-considerations)
- [Testing](#testing)
- [License](#license)

## Installation

```bash
composer require tourze/tls-crypto-hash
```

## Requirements

- PHP 8.1 or higher
- ext-hash extension
- ext-openssl extension
- ext-gmp extension

## Features

- **Hash Functions**: SHA-256, SHA-384, SHA-512, SHA-1, MD5
- **Message Authentication Codes**: HMAC, GMAC, Poly1305
- **Key Derivation Functions**: HKDF (RFC 5869), PBKDF2
- **TLS-Specific**: TLS 1.2 PRF, TLS 1.3 HKDF
- **Streaming Support**: Context-based hashing for large data
- **Security**: Constant-time comparison, proper error handling

## Usage

### Hash Functions

```php
use Tourze\TLSCryptoHash\HashFactory;

// Create a hash function
$hash = HashFactory::createHash('sha256');

// Simple hashing
$result = $hash->hash('Hello World');

// Streaming hashing for large data
$context = $hash->createContext();
$hash->updateContext($context, 'Hello ');
$hash->updateContext($context, 'World');
$result = $hash->finalizeContext($context);
```

### Message Authentication Code (MAC)

```php
use Tourze\TLSCryptoHash\HashFactory;

// Create HMAC-SHA256
$hmac = HashFactory::createMac('hmac-sha256');

$key = random_bytes(32);
$data = 'Sensitive data';

// Compute MAC
$mac = $hmac->compute($data, $key);

// Verify MAC (constant-time comparison)
$isValid = $hmac->verify($data, $mac, $key);
```

### Key Derivation Function (KDF)

```php
use Tourze\TLSCryptoHash\HashFactory;

// Create HKDF-SHA256
$kdf = HashFactory::createKdf('hkdf-sha256');

$secret = 'master secret';
$salt = 'salt value';
$info = 'context information';
$length = 32; // bytes

// Derive key material
$derivedKey = $kdf->derive($secret, $salt, $info, $length);
```

### PBKDF2 for Password Hashing

```php
use Tourze\TLSCryptoHash\HashFactory;

// Create PBKDF2-SHA256 with custom iterations
$kdf = HashFactory::createKdf('pbkdf2-sha256', [
    'iterations' => 100000
]);

$password = 'user password';
$salt = random_bytes(16);
$keyLength = 32;

$hashedPassword = $kdf->derive($password, $salt, '', $keyLength);
```

### Advanced MAC Examples

```php
use Tourze\TLSCryptoHash\HashFactory;

// GMAC (AES-GCM authentication)
$gmac = HashFactory::createMac('gmac-256');

// Poly1305 MAC
$poly1305 = HashFactory::createMac('poly1305');
```

## Advanced Usage

### TLS 1.2 and 1.3 Implementations

```php
use Tourze\TLSCryptoHash\Tls\TLS12PRF;
use Tourze\TLSCryptoHash\Tls\TLS13HKDF;

// TLS 1.2 Pseudo-Random Function
$prf = new TLS12PRF();
$keyBlock = $prf->compute($secret, $label, $seed, $length);

// TLS 1.3 HKDF-Expand-Label
$hkdf = new TLS13HKDF();
$derivedKey = $hkdf->expandLabel($secret, $label, $context, $length);
```

### Custom Configuration

```php
use Tourze\TLSCryptoHash\HashFactory;

// Create PBKDF2 with custom parameters
$kdf = HashFactory::createKdf('pbkdf2-sha512', [
    'iterations' => 200000,
    'salt_length' => 32
]);

// Create HMAC with specific output truncation
$hmac = HashFactory::createMac('hmac-sha256', [
    'truncate_length' => 16
]);
```

### Performance Optimization

```php
use Tourze\TLSCryptoHash\HashFactory;

// Use streaming for large files
$hash = HashFactory::createHash('sha256');
$context = $hash->createContext();

$file = fopen('large-file.bin', 'rb');
while (!feof($file)) {
    $chunk = fread($file, 8192);
    $hash->updateContext($context, $chunk);
}
fclose($file);

$fileHash = $hash->finalizeContext($context);
```

## Supported Algorithms

### Hash Functions
- `sha256` - SHA-256 (recommended)
- `sha384` - SHA-384
- `sha512` - SHA-512
- `sha1` - SHA-1 (legacy)
- `md5` - MD5 (legacy, not recommended)

### MAC Algorithms
- `hmac-{hash}` - HMAC with specified hash function
- `gmac-{128|192|256}` - GMAC with specified key size
- `poly1305` - Poly1305 MAC

### KDF Algorithms
- `hkdf-{hash}` - HKDF with specified hash function
- `pbkdf2-{hash}` - PBKDF2 with specified hash function

## Security Considerations

- This library uses PHP's built-in cryptographic functions
- Constant-time comparison is used for MAC verification
- Legacy algorithms (MD5, SHA-1) are included for compatibility only
- Use strong hash functions (SHA-256 or higher) for new implementations
- Always use proper key management practices

## Testing

```bash
./vendor/bin/phpunit packages/tls-crypto-hash/tests
```

## Contributing

Please feel free to contribute to this project by:

- Reporting bugs via [GitHub Issues](https://github.com/tourze/php-monorepo/issues)
- Submitting feature requests
- Creating pull requests with bug fixes or new features

When contributing code:

1. Follow PSR-12 coding standards
2. Write comprehensive tests for new features
3. Ensure all tests pass before submitting
4. Update documentation as needed

### Development Setup

```bash
# Clone the repository
git clone https://github.com/tourze/php-monorepo.git
cd php-monorepo

# Install dependencies
composer install

# Run tests
./vendor/bin/phpunit packages/tls-crypto-hash/tests

# Run static analysis
php -d memory_limit=2G ./vendor/bin/phpstan analyse packages/tls-crypto-hash
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for details about version changes.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
