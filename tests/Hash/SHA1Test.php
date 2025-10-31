<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoHash\Tests\Hash;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoHash\Hash\SHA1;
use Tourze\TLSCryptoHash\HashFactory;

/**
 * SHA-1哈希函数测试
 *
 * @internal
 */
#[CoversClass(SHA1::class)]
final class SHA1Test extends TestCase
{
    /**
     * 测试获取哈希算法名称
     */
    public function testGetName(): void
    {
        $sha1 = new SHA1();
        $this->assertEquals('sha1', $sha1->getName());
    }

    /**
     * 测试获取哈希输出长度
     */
    public function testGetOutputLength(): void
    {
        $sha1 = new SHA1();
        $this->assertEquals(20, $sha1->getOutputLength());
    }

    /**
     * 测试获取哈希块大小
     */
    public function testGetBlockSize(): void
    {
        $sha1 = new SHA1();
        $this->assertEquals(64, $sha1->getBlockSize());
    }

    /**
     * 测试计算数据的哈希值
     */
    public function testHash(): void
    {
        $sha1 = new SHA1();
        $data = 'test data';
        $hash = $sha1->hash($data);

        // 验证哈希长度正确
        $this->assertEquals(20, strlen($hash));

        // 验证哈希值正确
        $expectedHash = hash('sha1', $data, true);
        $this->assertEquals($expectedHash, $hash);
    }

    /**
     * 测试使用哈希上下文计算哈希值
     */
    public function testHashWithContext(): void
    {
        $sha1 = new SHA1();
        $data1 = 'part1';
        $data2 = 'part2';

        // 直接计算整个数据的哈希值
        $expectedHash = $sha1->hash($data1 . $data2);

        // 使用上下文分段计算哈希值
        $context = $sha1->createContext();
        $sha1->updateContext($context, $data1);
        $sha1->updateContext($context, $data2);
        $actualHash = $sha1->finalizeContext($context);

        $this->assertEquals($expectedHash, $actualHash);
    }

    /**
     * 测试通过工厂类创建哈希函数
     */
    public function testCreateThroughFactory(): void
    {
        $sha1 = HashFactory::createHash('sha1');
        $this->assertInstanceOf(SHA1::class, $sha1);
        $this->assertEquals('sha1', $sha1->getName());
    }

    /**
     * 测试空字符串的哈希值
     */
    public function testEmptyStringHash(): void
    {
        $sha1 = new SHA1();
        $hash = $sha1->hash('');
        $expectedHash = hash('sha1', '', true);
        $this->assertEquals($expectedHash, $hash);
    }

    /**
     * 测试长数据的哈希值
     */
    public function testLongDataHash(): void
    {
        $sha1 = new SHA1();
        $data = str_repeat('a', 1000000); // 100万个'a'

        $hash = $sha1->hash($data);
        $expectedHash = hash('sha1', $data, true);
        $this->assertEquals($expectedHash, $hash);
    }

    /**
     * 测试创建哈希上下文
     */
    public function testCreateContext(): void
    {
        $sha1 = new SHA1();
        $context = $sha1->createContext();
        $this->assertTrue($context instanceof \HashContext || is_resource($context));
    }

    /**
     * 测试更新哈希上下文
     */
    public function testUpdateContext(): void
    {
        $sha1 = new SHA1();
        $context = $sha1->createContext();
        $data = 'test data';

        // 测试更新操作不抛出异常
        $sha1->updateContext($context, $data);

        // 验证上下文状态仍然有效，可以继续使用
        $this->assertTrue($context instanceof \HashContext || is_resource($context));
    }

    /**
     * 测试完成哈希计算
     */
    public function testFinalizeContext(): void
    {
        $sha1 = new SHA1();
        $context = $sha1->createContext();
        $data = 'test data';

        $sha1->updateContext($context, $data);
        $hash = $sha1->finalizeContext($context);

        $this->assertIsString($hash);
        $this->assertEquals(20, strlen($hash));

        // 验证结果与直接哈希计算一致
        $expectedHash = $sha1->hash($data);
        $this->assertEquals($expectedHash, $hash);
    }
}
