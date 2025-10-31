# TLS-Crypto-Hash

[English](README.md) | [中文](README.zh-CN.md)

[![Latest Version](https://img.shields.io/packagist/v/tourze/tls-crypto-hash.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-crypto-hash)
[![PHP Version](https://img.shields.io/badge/php-%3E%3D8.1-brightgreen.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-crypto-hash)
[![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](LICENSE)
[![Coverage](https://img.shields.io/badge/coverage-%3E90%25-brightgreen.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-crypto-hash)
[![Total Downloads](https://img.shields.io/packagist/dt/tourze/tls-crypto-hash.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-crypto-hash)

为 TLS 协议实现设计的全面的 PHP 加密库，提供哈希函数、消息认证码（MAC）和密钥导出函数（KDF）。

## 目录

- [安装](#安装)
- [系统要求](#系统要求)
- [功能特性](#功能特性)
- [使用方法](#使用方法)
  - [哈希函数](#哈希函数)
  - [消息认证码（MAC）](#消息认证码mac)
  - [密钥导出函数（KDF）](#密钥导出函数kdf)
  - [PBKDF2 密码哈希](#pbkdf2-密码哈希)
  - [高级 MAC 示例](#高级-mac-示例)
- [高级用法](#高级用法)
  - [TLS 1.2 和 1.3 实现](#tls-12-和-13-实现)
  - [自定义配置](#自定义配置)
  - [性能优化](#性能优化)
- [支持的算法](#支持的算法)
  - [哈希函数](#哈希函数)
  - [MAC 算法](#mac-算法)
  - [KDF 算法](#kdf-算法)
- [安全考虑](#安全考虑)
- [测试](#测试)
- [许可证](#许可证)

## 安装

```bash
composer require tourze/tls-crypto-hash
```

## 系统要求

- PHP 8.1 或更高版本
- ext-hash 扩展
- ext-openssl 扩展
- ext-gmp 扩展

## 功能特性

- **哈希函数**：SHA-256、SHA-384、SHA-512、SHA-1、MD5
- **消息认证码**：HMAC、GMAC、Poly1305
- **密钥导出函数**：HKDF（RFC 5869）、PBKDF2
- **TLS 专用**：TLS 1.2 PRF、TLS 1.3 HKDF
- **流式支持**：基于上下文的大数据哈希处理
- **安全性**：恒定时间比较、适当的错误处理

## 使用方法

### 哈希函数

```php
use Tourze\TLSCryptoHash\HashFactory;

// 创建哈希函数
$hash = HashFactory::createHash('sha256');

// 简单哈希
$result = $hash->hash('Hello World');

// 大数据流式哈希
$context = $hash->createContext();
$hash->updateContext($context, 'Hello ');
$hash->updateContext($context, 'World');
$result = $hash->finalizeContext($context);
```

### 消息认证码（MAC）

```php
use Tourze\TLSCryptoHash\HashFactory;

// 创建 HMAC-SHA256
$hmac = HashFactory::createMac('hmac-sha256');

$key = random_bytes(32);
$data = 'Sensitive data';

// 计算 MAC
$mac = $hmac->compute($data, $key);

// 验证 MAC（恒定时间比较）
$isValid = $hmac->verify($data, $mac, $key);
```

### 密钥导出函数（KDF）

```php
use Tourze\TLSCryptoHash\HashFactory;

// 创建 HKDF-SHA256
$kdf = HashFactory::createKdf('hkdf-sha256');

$secret = 'master secret';
$salt = 'salt value';
$info = 'context information';
$length = 32; // 字节

// 导出密钥材料
$derivedKey = $kdf->derive($secret, $salt, $info, $length);
```

### PBKDF2 密码哈希

```php
use Tourze\TLSCryptoHash\HashFactory;

// 创建带自定义迭代次数的 PBKDF2-SHA256
$kdf = HashFactory::createKdf('pbkdf2-sha256', [
    'iterations' => 100000
]);

$password = 'user password';
$salt = random_bytes(16);
$keyLength = 32;

$hashedPassword = $kdf->derive($password, $salt, '', $keyLength);
```

### 高级 MAC 示例

```php
use Tourze\TLSCryptoHash\HashFactory;

// GMAC（AES-GCM 认证）
$gmac = HashFactory::createMac('gmac-256');

// Poly1305 MAC
$poly1305 = HashFactory::createMac('poly1305');
```

## 高级用法

### TLS 1.2 和 1.3 实现

```php
use Tourze\TLSCryptoHash\Tls\TLS12PRF;
use Tourze\TLSCryptoHash\Tls\TLS13HKDF;

// TLS 1.2 伪随机函数
$prf = new TLS12PRF();
$keyBlock = $prf->compute($secret, $label, $seed, $length);

// TLS 1.3 HKDF-Expand-Label
$hkdf = new TLS13HKDF();
$derivedKey = $hkdf->expandLabel($secret, $label, $context, $length);
```

### 自定义配置

```php
use Tourze\TLSCryptoHash\HashFactory;

// 使用自定义参数创建 PBKDF2
$kdf = HashFactory::createKdf('pbkdf2-sha512', [
    'iterations' => 200000,
    'salt_length' => 32
]);

// 创建指定输出截断的 HMAC
$hmac = HashFactory::createMac('hmac-sha256', [
    'truncate_length' => 16
]);
```

### 性能优化

```php
use Tourze\TLSCryptoHash\HashFactory;

// 对大文件使用流式处理
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

## 支持的算法

### 哈希函数
- `sha256` - SHA-256（推荐）
- `sha384` - SHA-384
- `sha512` - SHA-512
- `sha1` - SHA-1（传统）
- `md5` - MD5（传统，不推荐）

### MAC 算法
- `hmac-{hash}` - 使用指定哈希函数的 HMAC
- `gmac-{128|192|256}` - 使用指定密钥大小的 GMAC
- `poly1305` - Poly1305 MAC

### KDF 算法
- `hkdf-{hash}` - 使用指定哈希函数的 HKDF
- `pbkdf2-{hash}` - 使用指定哈希函数的 PBKDF2

## 安全考虑

- 此库使用 PHP 的内置加密函数
- MAC 验证使用恒定时间比较
- 传统算法（MD5、SHA-1）仅为兼容性而包含
- 新实现请使用强哈希函数（SHA-256 或更高）
- 始终使用适当的密钥管理实践

## 测试

```bash
./vendor/bin/phpunit packages/tls-crypto-hash/tests
```

## 贡献指南

欢迎为本项目做出贡献：

- 通过 [GitHub Issues](https://github.com/tourze/php-monorepo/issues) 报告错误
- 提交功能请求
- 创建修复错误或新功能的拉取请求

贡献代码时：

1. 遵循 PSR-12 编码标准
2. 为新功能编写全面的测试
3. 提交前确保所有测试通过
4. 根据需要更新文档

### 开发环境设置

```bash
# 克隆仓库
git clone https://github.com/tourze/php-monorepo.git
cd php-monorepo

# 安装依赖
composer install

# 运行测试
./vendor/bin/phpunit packages/tls-crypto-hash/tests

# 运行静态分析
php -d memory_limit=2G ./vendor/bin/phpstan analyse packages/tls-crypto-hash
```

## 更新日志

查看 [CHANGELOG.md](CHANGELOG.md) 了解版本更改详情。

## 许可证

本项目采用 MIT 许可证 - 请查看 [LICENSE](LICENSE) 文件了解详情。
