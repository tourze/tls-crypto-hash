<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoHash\Tests\Tls;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoHash\Tls\TLS13HKDF;

/**
 * TLS 1.3 HKDF测试
 *
 * @internal
 */
#[CoversClass(TLS13HKDF::class)]
final class TLS13HKDFTest extends TestCase
{
    /**
     * 测试HKDF-Extract函数
     */
    public function testExtract(): void
    {
        $hkdf = new TLS13HKDF();
        $salt = random_bytes(32);
        $ikm = random_bytes(32);

        $result = $hkdf->extract($salt, $ikm);

        $this->assertNotEmpty($result);
        $this->assertSame(32, strlen($result)); // SHA-256输出长度为32字节
    }

    /**
     * 测试HKDF-Expand-Label函数
     */
    public function testExpandLabel(): void
    {
        $hkdf = new TLS13HKDF();
        $secret = random_bytes(32);
        $label = 'derived';
        $context = '';

        $result1 = $hkdf->expandLabel($secret, $label, $context, 16);
        $result2 = $hkdf->expandLabel($secret, $label, $context, 32);

        $this->assertSame(16, strlen($result1));
        $this->assertSame(32, strlen($result2));

        // 测试相同输入产生相同输出
        $result3 = $hkdf->expandLabel($secret, $label, $context, 32);
        $this->assertSame($result2, $result3);
    }

    /**
     * 测试Derive-Secret函数
     */
    public function testDeriveSecret(): void
    {
        $hkdf = new TLS13HKDF();
        $secret = random_bytes(32);
        $label = 'c hs traffic';
        $messages = 'ClientHello + ServerHello';

        $result = $hkdf->deriveSecret($secret, $label, $messages);

        $this->assertNotEmpty($result);
        $this->assertSame(32, strlen($result)); // SHA-256输出长度为32字节

        // 测试不同消息产生不同输出
        $result2 = $hkdf->deriveSecret($secret, $label, 'Different messages');
        $this->assertNotSame($result, $result2);
    }

    /**
     * 测试RFC 8446中的HKDF测试向量
     * 注意：这是一个假设的测试向量，实际实现中应替换为规范中的真实测试向量
     */
    public function testHKDFVectors(): void
    {
        $hkdf = new TLS13HKDF();

        // 测试向量（在实际实现中替换为真实测试数据）
        $ikm = hex2bin('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
        $this->assertNotFalse($ikm);
        $salt = hex2bin('000102030405060708090a0b0c');
        $this->assertNotFalse($salt);
        $info = hex2bin('f0f1f2f3f4f5f6f7f8f9');
        $this->assertNotFalse($info);
        $length = 42;

        $prk = $hkdf->extract($salt, $ikm);
        $result = $hkdf->expand($prk, $info, $length);

        $this->assertSame($length, strlen($result));
    }

    /**
     * 测试deriveEarlySecret方法
     */
    public function testDeriveEarlySecret(): void
    {
        $hkdf = new TLS13HKDF();

        // 测试不带PSK的情况
        $earlySecret1 = $hkdf->deriveEarlySecret();
        $this->assertIsString($earlySecret1);
        $this->assertEquals(32, strlen($earlySecret1)); // SHA-256输出32字节

        // 测试带PSK的情况
        $psk = random_bytes(32);
        $earlySecret2 = $hkdf->deriveEarlySecret($psk);
        $this->assertIsString($earlySecret2);
        $this->assertEquals(32, strlen($earlySecret2));

        // 不同PSK应产生不同结果
        $this->assertNotEquals($earlySecret1, $earlySecret2);

        // 相同PSK应产生相同结果
        $earlySecret3 = $hkdf->deriveEarlySecret($psk);
        $this->assertEquals($earlySecret2, $earlySecret3);
    }

    /**
     * 测试deriveHandshakeSecret方法
     */
    public function testDeriveHandshakeSecret(): void
    {
        $hkdf = new TLS13HKDF();
        $earlySecret = $hkdf->deriveEarlySecret();
        $sharedSecret = random_bytes(32);

        $handshakeSecret = $hkdf->deriveHandshakeSecret($earlySecret, $sharedSecret);

        $this->assertIsString($handshakeSecret);
        $this->assertEquals(32, strlen($handshakeSecret)); // SHA-256输出32字节

        // 相同输入应产生相同输出
        $handshakeSecret2 = $hkdf->deriveHandshakeSecret($earlySecret, $sharedSecret);
        $this->assertEquals($handshakeSecret, $handshakeSecret2);

        // 不同 shared secret 应产生不同输出
        $differentSharedSecret = random_bytes(32);
        $handshakeSecret3 = $hkdf->deriveHandshakeSecret($earlySecret, $differentSharedSecret);
        $this->assertNotEquals($handshakeSecret, $handshakeSecret3);
    }

    /**
     * 测试deriveMasterSecret方法
     */
    public function testDeriveMasterSecret(): void
    {
        $hkdf = new TLS13HKDF();
        $earlySecret = $hkdf->deriveEarlySecret();
        $sharedSecret = random_bytes(32);
        $handshakeSecret = $hkdf->deriveHandshakeSecret($earlySecret, $sharedSecret);

        $masterSecret = $hkdf->deriveMasterSecret($handshakeSecret);

        $this->assertIsString($masterSecret);
        $this->assertEquals(32, strlen($masterSecret)); // SHA-256输出32字节

        // 相同输入应产生相同输出
        $masterSecret2 = $hkdf->deriveMasterSecret($handshakeSecret);
        $this->assertEquals($masterSecret, $masterSecret2);

        // 不同 handshake secret 应产生不同输出
        $differentHandshakeSecret = random_bytes(32);
        $masterSecret3 = $hkdf->deriveMasterSecret($differentHandshakeSecret);
        $this->assertNotEquals($masterSecret, $masterSecret3);
    }
}
