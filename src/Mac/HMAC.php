<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoHash\Mac;

use Tourze\TLSCryptoHash\Contract\HashInterface;
use Tourze\TLSCryptoHash\Contract\MacInterface;

/**
 * HMAC消息认证码实现
 */
class HMAC implements MacInterface
{
    /**
     * 构造函数
     *
     * @param HashInterface $hash 使用的哈希函数
     */
    public function __construct(private readonly HashInterface $hash)
    {
    }

    /**
     * 获取MAC算法名称
     */
    public function getName(): string
    {
        return 'hmac-' . $this->hash->getName();
    }

    /**
     * 获取MAC输出长度（字节）
     */
    public function getOutputLength(): int
    {
        return $this->hash->getOutputLength();
    }

    /**
     * 计算消息认证码
     *
     * @param string $data 要计算MAC的数据
     * @param string $key  密钥
     *
     * @return string MAC值
     */
    public function compute(string $data, string $key): string
    {
        return hash_hmac($this->hash->getName(), $data, $key, true);
    }

    /**
     * 验证消息认证码
     *
     * @param string $data 原始数据
     * @param string $mac  消息认证码
     * @param string $key  密钥
     *
     * @return bool MAC是否有效
     */
    public function verify(string $data, string $mac, string $key): bool
    {
        $computed = $this->compute($data, $key);

        // 使用恒定时间比较防止时间侧信道攻击
        return hash_equals($computed, $mac);
    }
}
