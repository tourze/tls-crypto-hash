<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoHash\Hash;

use Tourze\TLSCryptoHash\Contract\HashInterface;

/**
 * SHA-384哈希函数实现
 */
class SHA384 implements HashInterface
{
    /**
     * 获取哈希算法名称
     */
    public function getName(): string
    {
        return 'sha384';
    }

    /**
     * 获取哈希输出长度（字节）
     */
    public function getOutputLength(): int
    {
        return 48; // 384位 = 48字节
    }

    /**
     * 获取哈希块大小（字节）
     */
    public function getBlockSize(): int
    {
        return 128; // SHA-384的块大小为128字节
    }

    /**
     * 计算数据的哈希值
     *
     * @param string $data 要计算哈希的数据
     *
     * @return string 哈希值
     */
    public function hash(string $data): string
    {
        return hash('sha384', $data, true);
    }

    /**
     * 创建哈希上下文
     *
     * @return \HashContext 哈希上下文
     */
    public function createContext()
    {
        return hash_init('sha384');
    }

    /**
     * 更新哈希上下文
     *
     * @param resource|object $context 哈希上下文
     * @param string          $data    要添加到哈希计算的数据
     */
    public function updateContext($context, string $data): void
    {
        assert($context instanceof \HashContext);
        hash_update($context, $data);
    }

    /**
     * 完成哈希计算
     *
     * @param resource|object $context 哈希上下文
     *
     * @return string 最终的哈希值
     */
    public function finalizeContext($context): string
    {
        assert($context instanceof \HashContext);

        return hash_final($context, true);
    }
}
