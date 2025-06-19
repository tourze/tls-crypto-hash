<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoHash\Hash;

use Tourze\TLSCryptoHash\Contract\HashInterface;

/**
 * SHA-1哈希函数实现
 *
 * 安全警告：SHA-1被认为是不安全的，已经被密码学家成功碰撞。
 * 它不应该用于数字签名、证书或其他需要抗碰撞保护的应用场景。
 * 仅在需要兼容旧系统或遗留协议时使用。
 * 对于安全敏感的应用，应使用SHA-256或更强的哈希函数。
 */
class SHA1 implements HashInterface
{
    /**
     * 获取哈希算法名称
     *
     * @return string
     */
    public function getName(): string
    {
        return 'sha1';
    }

    /**
     * 获取哈希输出长度（字节）
     *
     * @return int
     */
    public function getOutputLength(): int
    {
        return 20; // 160位 = 20字节
    }

    /**
     * 获取哈希块大小（字节）
     *
     * @return int
     */
    public function getBlockSize(): int
    {
        return 64; // SHA-1的块大小为64字节
    }

    /**
     * 计算数据的哈希值
     *
     * @param string $data 要计算哈希的数据
     * @return string 哈希值
     */
    public function hash(string $data): string
    {
        return hash('sha1', $data, true);
    }

    /**
     * 创建哈希上下文
     *
     * @return \HashContext 哈希上下文
     */
    public function createContext()
    {
        return hash_init('sha1');
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
