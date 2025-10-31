<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoHash\Tests\Hash;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoHash\Hash\SHA512;

/**
 * SHA512测试类
 *
 * @internal
 */
#[CoversClass(SHA512::class)]
final class SHA512Test extends TestCase
{
    private SHA512 $hash;

    /**
     * 测试获取哈希算法名称
     */
    public function testGetName(): void
    {
        $this->assertEquals('sha512', $this->hash->getName());
    }

    /**
     * 测试获取哈希输出长度
     */
    public function testGetOutputLength(): void
    {
        $this->assertEquals(64, $this->hash->getOutputLength()); // 512位 = 64字节
    }

    /**
     * 测试获取哈希块大小
     */
    public function testGetBlockSize(): void
    {
        $this->assertEquals(128, $this->hash->getBlockSize()); // SHA-512块大小为128字节
    }

    /**
     * 测试哈希计算
     */
    public function testHash(): void
    {
        $data = 'Hello, World!';
        $expected = hash('sha512', $data, true);

        $result = $this->hash->hash($data);

        $this->assertEquals($expected, $result);
        $this->assertEquals(64, strlen($result));
    }

    /**
     * 测试空字符串的哈希值
     */
    public function testHashEmptyString(): void
    {
        $expected = hash('sha512', '', true);
        $result = $this->hash->hash('');

        $this->assertEquals($expected, $result);
    }

    /**
     * 测试增量哈希计算
     */
    public function testIncrementalHash(): void
    {
        $part1 = 'Hello, ';
        $part2 = 'World!';
        $fullData = $part1 . $part2;

        // 直接计算完整数据的哈希
        $expectedHash = $this->hash->hash($fullData);

        // 使用增量方式计算哈希
        $context = $this->hash->createContext();
        $this->hash->updateContext($context, $part1);
        $this->hash->updateContext($context, $part2);
        $incrementalHash = $this->hash->finalizeContext($context);

        $this->assertEquals($expectedHash, $incrementalHash);
    }

    /**
     * 测试创建哈希上下文
     */
    public function testCreateContext(): void
    {
        $context = $this->hash->createContext();
        $this->assertTrue($context instanceof \HashContext || is_resource($context));
    }

    /**
     * 测试更新哈希上下文
     */
    public function testUpdateContext(): void
    {
        $context = $this->hash->createContext();
        $data = 'test data';

        // 测试更新操作不抛出异常
        $this->hash->updateContext($context, $data);

        // 验证上下文状态仍然有效，可以继续使用
        $this->assertTrue($context instanceof \HashContext || is_resource($context));
    }

    /**
     * 测试完成哈希计算
     */
    public function testFinalizeContext(): void
    {
        $context = $this->hash->createContext();
        $data = 'test data';

        $this->hash->updateContext($context, $data);
        $hash = $this->hash->finalizeContext($context);

        $this->assertIsString($hash);
        $this->assertEquals(64, strlen($hash));

        // 验证结果与直接哈希计算一致
        $expectedHash = $this->hash->hash($data);
        $this->assertEquals($expectedHash, $hash);
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->hash = new SHA512();
    }
}
