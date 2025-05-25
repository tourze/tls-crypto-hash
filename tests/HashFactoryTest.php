<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoHash\Tests;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoHash\Exception\CryptoException;
use Tourze\TLSCryptoHash\Hash\SHA256;
use Tourze\TLSCryptoHash\HashFactory;
use Tourze\TLSCryptoHash\Kdf\HKDF;
use Tourze\TLSCryptoHash\Mac\HMAC;

/**
 * HashFactory测试用例
 */
class HashFactoryTest extends TestCase
{
    /**
     * 测试创建哈希函数
     */
    public function testCreateHash(): void
    {
        $hash = HashFactory::createHash('sha256');
        $this->assertInstanceOf(SHA256::class, $hash);
        $this->assertEquals('sha256', $hash->getName());
    }

    /**
     * 测试创建不支持的哈希函数
     */
    public function testCreateHashUnsupported(): void
    {
        $this->expectException(CryptoException::class);
        HashFactory::createHash('unsupported');
    }

    /**
     * 测试创建MAC
     */
    public function testCreateMac(): void
    {
        $mac = HashFactory::createMac('hmac-sha256');
        $this->assertInstanceOf(HMAC::class, $mac);
        $this->assertEquals('hmac-sha256', $mac->getName());
    }

    /**
     * 测试创建不支持的MAC
     */
    public function testCreateMacUnsupported(): void
    {
        $this->expectException(CryptoException::class);
        HashFactory::createMac('unsupported');
    }

    /**
     * 测试创建KDF
     */
    public function testCreateKdf(): void
    {
        $kdf = HashFactory::createKdf('hkdf-sha256');
        $this->assertInstanceOf(HKDF::class, $kdf);
        $this->assertEquals('hkdf-sha256', $kdf->getName());
    }

    /**
     * 测试创建不支持的KDF
     */
    public function testCreateKdfUnsupported(): void
    {
        $this->expectException(CryptoException::class);
        HashFactory::createKdf('unsupported');
    }

    /**
     * 测试HMAC计算和验证
     */
    public function testHmacComputeVerify(): void
    {
        $hmac = HashFactory::createMac('hmac-sha256');

        $key = random_bytes(32);
        $data = 'Test Message';

        $mac = $hmac->compute($data, $key);
        $this->assertTrue($hmac->verify($data, $mac, $key));
        $this->assertFalse($hmac->verify('Wrong Message', $mac, $key));
    }

    /**
     * 测试HKDF密钥导出
     */
    public function testHkdfDerive(): void
    {
        $kdf = HashFactory::createKdf('hkdf-sha256');

        $secret = 'master secret';
        $salt = 'salt value';
        $info = 'context information';
        $length = 32;

        $key1 = $kdf->derive($secret, $salt, $info, $length);
        $key2 = $kdf->derive($secret, $salt, $info, $length);

        $this->assertEquals($length, strlen($key1));
        $this->assertEquals($key1, $key2);

        // 不同的info应该产生不同的密钥
        $key3 = $kdf->derive($secret, $salt, 'different info', $length);
        $this->assertNotEquals($key1, $key3);
    }
} 