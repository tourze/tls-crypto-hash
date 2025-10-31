<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoHash;

use Tourze\TLSCryptoHash\Contract\HashInterface;
use Tourze\TLSCryptoHash\Contract\KdfInterface;
use Tourze\TLSCryptoHash\Contract\MacInterface;
use Tourze\TLSCryptoHash\Exception\HashException;
use Tourze\TLSCryptoHash\Exception\KdfException;
use Tourze\TLSCryptoHash\Exception\MacException;
use Tourze\TLSCryptoHash\Hash\MD5;
use Tourze\TLSCryptoHash\Hash\SHA1;
use Tourze\TLSCryptoHash\Hash\SHA256;
use Tourze\TLSCryptoHash\Hash\SHA384;
use Tourze\TLSCryptoHash\Hash\SHA512;
use Tourze\TLSCryptoHash\Kdf\HKDF;
use Tourze\TLSCryptoHash\Kdf\PBKDF2;
use Tourze\TLSCryptoHash\Mac\GMAC;
use Tourze\TLSCryptoHash\Mac\HMAC;
use Tourze\TLSCryptoHash\Mac\Poly1305;

/**
 * 哈希、MAC和KDF工厂类
 */
class HashFactory
{
    /**
     * 创建哈希函数
     *
     * @param string $algorithm 哈希算法名称
     *
     * @throws HashException 如果算法不支持
     */
    public static function createHash(string $algorithm): HashInterface
    {
        return match ($algorithm) {
            'sha256' => new SHA256(),
            'sha384' => new SHA384(),
            'sha512' => new SHA512(),
            'sha1' => new SHA1(),
            'md5' => new MD5(),
            default => throw new HashException('不支持的哈希算法: ' . $algorithm),
        };
    }

    /**
     * 创建消息认证码
     *
     * @param string             $algorithm MAC算法名称
     * @param array<string,mixed> $options   选项
     *
     * @throws MacException 如果算法不支持
     */
    public static function createMac(string $algorithm, array $options = []): MacInterface
    {
        if (str_starts_with($algorithm, 'hmac-')) {
            $hashAlgorithm = substr($algorithm, 5);
            $hash = self::createHash($hashAlgorithm);

            return new HMAC($hash);
        }

        if (str_starts_with($algorithm, 'gmac-')) {
            $keySize = (int) substr($algorithm, 5);
            if (!in_array($keySize, [128, 192, 256], true)) {
                throw new MacException('无效的GMAC密钥大小，有效值为128、192或256位');
            }

            return new GMAC($keySize);
        }

        if ('poly1305' === $algorithm) {
            return new Poly1305();
        }

        throw new MacException('不支持的MAC算法: ' . $algorithm);
    }

    /**
     * 创建密钥导出函数
     *
     * @param string             $algorithm KDF算法名称
     * @param array<string,mixed> $options   选项
     *
     * @throws KdfException 如果算法不支持
     */
    public static function createKdf(string $algorithm, array $options = []): KdfInterface
    {
        if (str_starts_with($algorithm, 'hkdf-')) {
            $hashAlgorithm = substr($algorithm, 5);
            $hash = self::createHash($hashAlgorithm);

            return new HKDF($hash);
        }

        if (str_starts_with($algorithm, 'pbkdf2-')) {
            $hashAlgorithm = substr($algorithm, 7);
            $hash = self::createHash($hashAlgorithm);
            $iterationsValue = $options['iterations'] ?? 10000;
            $iterations = is_int($iterationsValue) ? $iterationsValue : 10000;

            return new PBKDF2($hash, $iterations);
        }

        throw new KdfException('不支持的KDF算法: ' . $algorithm);
    }
}
