<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoHash\Hash;

use Tourze\TLSCryptoHash\Contract\HashInterface;
use Tourze\TLSCryptoHash\Exception\HashException;

/**
 * SHA-384哈希函数实现
 */
class SHA384 implements HashInterface
{
    /**
     * 获取哈希算法名称
     *
     * @return string
     */
    public function getName(): string
    {
        return 'sha384';
    }

    /**
     * 获取哈希输出长度（字节）
     *
     * @return int
     */
    public function getOutputLength(): int
    {
        return 48; // 384位 = 48字节
    }

    /**
     * 获取哈希块大小（字节）
     *
     * @return int
     */
    public function getBlockSize(): int
    {
        return 128; // SHA-384的块大小为128字节
    }

    /**
     * 计算数据的哈希值
     *
     * @param string $data 要计算哈希的数据
     * @return string 哈希值
     */
    public function hash(string $data): string
    {
        return hash('sha384', $data, true);
    }

    /**
     * 创建哈希上下文
     *
     * @return resource|object 哈希上下文
     * @throws HashException 如果创建上下文失败
     */
    public function createContext()
    {
        $context = hash_init('sha384');
        if ($context === false) {
            throw new HashException('无法初始化SHA-384哈希上下文');
        }
        return $context;
    }

    /**
     * 更新哈希上下文
     *
     * @param resource|object $context 哈希上下文
     * @param string $data 要添加到哈希计算的数据
     * @return void
     */
    public function updateContext($context, string $data): void
    {
        hash_update($context, $data);
    }

    /**
     * 完成哈希计算
     *
     * @param resource|object $context 哈希上下文
     * @return string 最终的哈希值
     */
    public function finalizeContext($context): string
    {
        return hash_final($context, true);
    }
} 