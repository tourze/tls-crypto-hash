<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoHash\Hash;

use Tourze\TLSCryptoHash\Contract\HashInterface;

/**
 * MD5哈希函数实现
 *
 * 严重安全警告：MD5被认为是完全不安全的，已被成功碰撞且计算速度非常快。
 * 它不应该用于任何安全场景，包括但不限于：
 * - 数字签名
 * - 密码存储
 * - 安全令牌
 * - 证书验证
 * - 数据完整性保护
 *
 * 此实现仅用于兼容旧系统或协议，或在不涉及安全的场景下使用。
 * 对于任何安全相关的用途，请使用SHA-256或更强的哈希函数。
 */
class MD5 implements HashInterface
{
    /**
     * 获取哈希算法名称
     */
    public function getName(): string
    {
        return 'md5';
    }

    /**
     * 获取哈希输出长度（字节）
     */
    public function getOutputLength(): int
    {
        return 16; // 128位 = 16字节
    }

    /**
     * 获取哈希块大小（字节）
     */
    public function getBlockSize(): int
    {
        return 64; // MD5的块大小为64字节
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
        return hash('md5', $data, true);
    }

    /**
     * 创建哈希上下文
     *
     * @return \HashContext 哈希上下文
     */
    public function createContext()
    {
        return hash_init('md5');
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
