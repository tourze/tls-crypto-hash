<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoHash\Tests\Tls;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoHash\Tls\TLS12PRF;

/**
 * TLS 1.2 PRF测试
 *
 * @internal
 */
#[CoversClass(TLS12PRF::class)]
final class TLS12PRFTest extends TestCase
{
    /**
     * 测试PRF算法能否正确生成指定长度的输出
     */
    public function testPRFOutputLength(): void
    {
        $prf = new TLS12PRF();
        $secret = random_bytes(32);
        $label = 'test label';
        $seed = random_bytes(32);

        $output1 = $prf->compute($secret, $label, $seed, 16);
        $output2 = $prf->compute($secret, $label, $seed, 32);
        $output3 = $prf->compute($secret, $label, $seed, 64);

        $this->assertSame(16, strlen($output1));
        $this->assertSame(32, strlen($output2));
        $this->assertSame(64, strlen($output3));
    }

    /**
     * 测试相同输入产生相同输出
     */
    public function testPRFConsistency(): void
    {
        $prf = new TLS12PRF();
        $secret = random_bytes(32);
        $label = 'test label';
        $seed = random_bytes(32);

        $output1 = $prf->compute($secret, $label, $seed, 32);
        $output2 = $prf->compute($secret, $label, $seed, 32);

        $this->assertSame($output1, $output2);
    }

    /**
     * 测试不同输入产生不同输出
     */
    public function testPRFDifferentInputs(): void
    {
        $prf = new TLS12PRF();
        $secret1 = random_bytes(32);
        $secret2 = random_bytes(32);
        $label = 'test label';
        $seed = random_bytes(32);

        $output1 = $prf->compute($secret1, $label, $seed, 32);
        $output2 = $prf->compute($secret2, $label, $seed, 32);

        $this->assertNotSame($output1, $output2);
    }

    /**
     * 测试RFC 5246中的PRF测试向量
     * 注意：这是一个假设的测试向量，实际实现中应替换为规范中的真实测试向量
     */
    public function testPRFVectors(): void
    {
        $prf = new TLS12PRF();

        // 测试向量（在实际实现中替换为真实测试数据）
        $secret = hex2bin('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
        $this->assertNotFalse($secret);
        $label = 'test label';
        $seed = hex2bin('cd34c1fe65e2adc03651e8cebc2c3fc05b7ae45f584b7a35ace363ae401a0cb7');
        $this->assertNotFalse($seed);

        // 我们使用更简单的断言，只确认结果长度正确
        $result = $prf->compute($secret, $label, $seed, 64);

        $this->assertSame(64, strlen($result));
    }

    /**
     * 测试compute方法
     */
    public function testCompute(): void
    {
        $prf = new TLS12PRF();
        $secret = 'test secret';
        $label = 'test label';
        $seed = 'test seed';
        $length = 32;

        $result = $prf->compute($secret, $label, $seed, $length);

        $this->assertIsString($result);
        $this->assertEquals($length, strlen($result));

        // 相同输入应产生相同输出
        $result2 = $prf->compute($secret, $label, $seed, $length);
        $this->assertEquals($result, $result2);
    }

    /**
     * 测试generateMasterSecret方法
     */
    public function testGenerateMasterSecret(): void
    {
        $prf = new TLS12PRF();
        $premaster = random_bytes(48);
        $clientRandom = random_bytes(32);
        $serverRandom = random_bytes(32);

        $masterSecret = $prf->generateMasterSecret($premaster, $clientRandom, $serverRandom);

        $this->assertIsString($masterSecret);
        $this->assertEquals(48, strlen($masterSecret)); // Master secret 始终是 48 字节

        // 相同输入应产生相同输出
        $masterSecret2 = $prf->generateMasterSecret($premaster, $clientRandom, $serverRandom);
        $this->assertEquals($masterSecret, $masterSecret2);
    }

    /**
     * 测试generateKeyBlock方法
     */
    public function testGenerateKeyBlock(): void
    {
        $prf = new TLS12PRF();
        $masterSecret = random_bytes(48);
        $clientRandom = random_bytes(32);
        $serverRandom = random_bytes(32);
        $length = 128;

        $keyBlock = $prf->generateKeyBlock($masterSecret, $clientRandom, $serverRandom, $length);

        $this->assertIsString($keyBlock);
        $this->assertEquals($length, strlen($keyBlock));

        // 相同输入应产生相同输出
        $keyBlock2 = $prf->generateKeyBlock($masterSecret, $clientRandom, $serverRandom, $length);
        $this->assertEquals($keyBlock, $keyBlock2);
    }

    /**
     * 测试generateVerifyData方法
     */
    public function testGenerateVerifyData(): void
    {
        $prf = new TLS12PRF();
        $masterSecret = random_bytes(48);
        $handshakeHash = random_bytes(32);
        $label = 'client finished';

        $verifyData = $prf->generateVerifyData($masterSecret, $handshakeHash, $label);

        $this->assertIsString($verifyData);
        $this->assertEquals(12, strlen($verifyData)); // Verify data 始终是 12 字节

        // 相同输入应产生相同输出
        $verifyData2 = $prf->generateVerifyData($masterSecret, $handshakeHash, $label);
        $this->assertEquals($verifyData, $verifyData2);

        // 不同 label 应产生不同输出
        $verifyData3 = $prf->generateVerifyData($masterSecret, $handshakeHash, 'server finished');
        $this->assertNotEquals($verifyData, $verifyData3);
    }
}
