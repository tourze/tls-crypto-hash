<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoHash\Mac;

use Tourze\TLSCryptoHash\Contract\MacInterface;
use Tourze\TLSCryptoHash\Exception\MacException;

/**
 * Poly1305消息认证码实现
 * 使用原生PHP实现的标准Poly1305算法
 */
class Poly1305 implements MacInterface
{
    /**
     * 固定密钥长度（字节）
     */
    private const KEY_LENGTH = 32;

    /**
     * 获取MAC算法名称
     */
    public function getName(): string
    {
        return 'poly1305';
    }

    /**
     * 获取MAC输出长度（字节）
     */
    public function getOutputLength(): int
    {
        return 16; // Poly1305标签长度固定为16字节（128位）
    }

    /**
     * 计算消息认证码
     *
     * @param string $data 要计算MAC的数据
     * @param string $key  密钥（必须是32字节）
     *
     * @return string MAC值
     *
     * @throws MacException 如果计算MAC失败
     */
    public function compute(string $data, string $key): string
    {
        // 验证密钥长度
        if (self::KEY_LENGTH !== strlen($key)) {
            throw new MacException('Poly1305密钥长度必须是32字节');
        }

        try {
            // 使用GMP扩展处理大整数
            if (extension_loaded('gmp')) {
                return $this->computeWithGMP($data, $key);
            }

            // 使用符合RFC8439的纯PHP实现
            return $this->computePurePhp($data, $key);
        } catch (\Throwable $e) {
            throw new MacException('Poly1305计算失败: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * 使用GMP扩展计算Poly1305 MAC
     *
     * @param string $data 数据
     * @param string $key  密钥
     *
     * @return string MAC值
     */
    private function computeWithGMP(string $data, string $key): string
    {
        // 准备密钥材料
        [$r_gmp, $s_gmp] = $this->prepareGmpKeyMaterial($key);

        // 处理消息数据
        $h_gmp = $this->processMessageWithGmp($data, $r_gmp);

        // 生成最终MAC
        return $this->generateMacFromGmp($h_gmp, $s_gmp);
    }

    /**
     * 准备GMP密钥材料
     *
     * @return array<int, \GMP> 包含[$r_gmp, $s_gmp]的数组
     */
    private function prepareGmpKeyMaterial(string $key): array
    {
        // 分离密钥的两部分
        $r = substr($key, 0, 16);
        $s = substr($key, 16, 16);

        // 将r转换为小端序的整数格式并应用clamp
        $r_int = $this->unpackLittleEndian($r);
        $r_int[0] &= 0x0FFFFFFF;
        $r_int[1] &= 0x0FFFFFFC;
        $r_int[2] &= 0x0FFFFFFC;
        $r_int[3] &= 0x0FFFFFFC;

        // 将s转换为小端序的整数
        $s_int = $this->unpackLittleEndian($s);

        // 转换为GMP对象
        $r_gmp = $this->convertToGmp($r_int);
        $s_gmp = $this->convertToGmp($s_int);

        return [$r_gmp, $s_gmp];
    }

    /**
     * 将整数数组转换为GMP对象
     *
     * @param array<int, int> $intArray 32位整数数组
     */
    private function convertToGmp(array $intArray): \GMP
    {
        $gmp = \gmp_init(0);
        for ($i = 0; $i < 4; ++$i) {
            $gmp = \gmp_add($gmp, \gmp_mul(\gmp_init($intArray[$i]), \gmp_pow(2, $i * 32)));
        }

        return $gmp;
    }

    /**
     * 使用GMP处理消息数据
     */
    private function processMessageWithGmp(string $data, \GMP $r_gmp): \GMP
    {
        // Poly1305素数: 2^130 - 5
        $p = \gmp_sub(\gmp_pow(2, 130), 5);
        $h_gmp = \gmp_init(0);

        // 分块处理消息
        $len = strlen($data);
        for ($i = 0; $i < $len; $i += 16) {
            $chunk = $this->prepareChunk($data, $i, $len);
            $n_gmp = $this->convertChunkToGmp($chunk);

            // h = (h + n) * r mod p
            $h_gmp = \gmp_add($h_gmp, $n_gmp);
            $h_gmp = \gmp_mod(\gmp_mul($h_gmp, $r_gmp), $p);
        }

        return $h_gmp;
    }

    /**
     * 准备消息块
     */
    private function prepareChunk(string $data, int $offset, int $totalLen): string
    {
        $chunk = substr($data, $offset, min(16, $totalLen - $offset));
        if (strlen($chunk) < 16) {
            $chunk = str_pad($chunk, 16, "\0");
        }

        return $chunk;
    }

    /**
     * 将消息块转换为GMP对象
     */
    private function convertChunkToGmp(string $chunk): \GMP
    {
        $chunk_int = $this->unpackLittleEndian($chunk);
        $n_gmp = $this->convertToGmp($chunk_int);

        // 添加高位1
        if (strlen($chunk) < 16) {
            $n_gmp = \gmp_add($n_gmp, \gmp_mul(\gmp_init(1), \gmp_pow(2, strlen($chunk) * 8)));
        } else {
            $n_gmp = \gmp_add($n_gmp, \gmp_mul(\gmp_init(1), \gmp_pow(2, 128)));
        }

        return $n_gmp;
    }

    /**
     * 从GMP对象生成最终MAC
     */
    private function generateMacFromGmp(\GMP $h_gmp, \GMP $s_gmp): string
    {
        // 添加s
        $h_gmp = \gmp_add($h_gmp, $s_gmp);

        // 将GMP对象转换为小端序的16字节MAC
        $h_hex = \gmp_strval($h_gmp, 16);
        $h_hex = str_pad($h_hex, 32, '0', STR_PAD_LEFT);

        $mac = '';
        for ($i = 0; $i < 16; ++$i) {
            $mac .= chr((int) hexdec(substr($h_hex, 30 - $i * 2, 2)));
        }

        return $mac;
    }

    /**
     * 使用纯PHP实现计算Poly1305 MAC
     *
     * 该实现避免超出PHP整数范围的大数计算
     *
     * @param string $data 数据
     * @param string $key  密钥
     *
     * @return string MAC值
     */
    private function computePurePhp(string $data, string $key): string
    {
        // 分离r和s
        $r = substr($key, 0, 16);
        $s = substr($key, 16, 16);

        // 获取r和s的字节数组（uint32数组）
        $r_uint = $this->unpackLittleEndian($r);
        $s_uint = $this->unpackLittleEndian($s);

        // 应用clamp到r
        $r_uint[0] &= 0x0FFFFFFF;
        $r_uint[1] &= 0x0FFFFFFC;
        $r_uint[2] &= 0x0FFFFFFC;
        $r_uint[3] &= 0x0FFFFFFC;

        // 初始化累加器
        $h_uint = [0, 0, 0, 0, 0];

        // 块处理
        $len = strlen($data);
        for ($i = 0; $i < $len; $i += 16) {
            $block = substr($data, $i, min(16, $len - $i));

            // 处理最后一个块的填充
            if (strlen($block) < 16) {
                $block = str_pad($block, 16, "\0");
                $n_uint = $this->unpackLittleEndian($block);
                // 添加一个高位1在消息末尾
                $msb_pos = strlen($block) - strlen(rtrim($block, "\0"));
                if ($msb_pos < 16) {
                    // 确定在哪个32位字中设置位
                    $word_idx = intdiv($msb_pos, 4);
                    $bit_idx = ($msb_pos % 4) * 8;
                    $n_uint[$word_idx] |= 1 << $bit_idx;
                }
            } else {
                $n_uint = $this->unpackLittleEndian($block);
                // 对于完整块，添加额外的字节和高位1
                $n_uint[] = 1;
            }

            // 将n加到h
            $h_uint = $this->addUnits($h_uint, $n_uint);

            // 计算h * r
            $h_uint = $this->multiplyAndReduce($h_uint, $r_uint);
        }

        // 添加s到h
        $h_uint = $this->addUnits($h_uint, $s_uint);

        // 打包结果
        $mac = '';
        for ($i = 0; $i < 4; ++$i) {
            $mac .= pack('V', $h_uint[$i]);
        }

        return $mac;
    }

    /**
     * 将字符串解包为小端序的uint32数组
     *
     * @param string $bytes 输入字节
     *
     * @return array<int, int> 返回uint32数组
     */
    private function unpackLittleEndian(string $bytes): array
    {
        $result = [];
        $len = strlen($bytes);

        // 每4个字节一组，解析为一个32位整数
        for ($i = 0; $i < $len; $i += 4) {
            if ($i + 4 <= $len) {
                $chunk = substr($bytes, $i, 4);
                $val = ord($chunk[0]) | (ord($chunk[1]) << 8) | (ord($chunk[2]) << 16) | (ord($chunk[3]) << 24);
                $result[] = $val;
            } else {
                // 处理不足4字节的尾部
                $val = 0;
                for ($j = 0; $j < $len - $i; ++$j) {
                    $val |= ord($bytes[$i + $j]) << ($j * 8);
                }
                $result[] = $val;
            }
        }

        return $result;
    }

    /**
     * 将两个uint32数组相加，返回结果数组
     *
     * @param array<int, int> $a 第一个数组
     * @param array<int, int> $b 第二个数组
     *
     * @return array<int, int> 相加后的结果数组
     */
    private function addUnits(array $a, array $b): array
    {
        $carry = 0;
        $a_len = count($a);
        $b_len = count($b);
        $len = max($a_len, $b_len);

        $result = $a;

        // 确保结果数组有足够的长度
        while (count($result) < $len) {
            $result[] = 0;
        }

        // 逐位相加，处理进位
        for ($i = 0; $i < $len; ++$i) {
            $a_val = $i < $a_len ? $result[$i] : 0;
            $b_val = $i < $b_len ? $b[$i] : 0;

            // 计算和，处理32位溢出
            $sum = $a_val + $b_val + $carry;
            $result[$i] = $sum & 0xFFFFFFFF; // 保留低32位
            $carry = ($sum >> 32) & 0x1; // 获取进位
        }

        // 如果还有进位，则添加到数组末尾
        if ($carry > 0) {
            $result[] = $carry;
        }

        return $result;
    }

    /**
     * 将h乘以r并模p，返回计算结果
     * 该实现避免超出PHP整数范围
     *
     * @param array<int, int> $h 累加器
     * @param array<int, int> $r r值
     *
     * @return array<int, int> 计算后的累加器
     */
    private function multiplyAndReduce(array $h, array $r): array
    {
        // 执行多项式乘法
        $result = $this->performPolynomialMultiplication($h, $r);

        // 执行模约简
        $result = $this->performModularReduction($result);

        // 返回结果
        return $this->updateAccumulator($result);
    }

    /**
     * 执行多项式乘法
     *
     * @param array<int, int> $h 累加器
     * @param array<int, int> $r r值
     *
     * @return array<int, int> 乘法结果数组
     */
    private function performPolynomialMultiplication(array $h, array $r): array
    {
        $result = [0, 0, 0, 0, 0];

        // 通过分解乘法为更小的部分来避免溢出
        for ($i = 0; $i < 4; ++$i) {
            $carry = 0;
            for ($j = 0; $j < 4; ++$j) {
                $products = $this->calculate32BitProducts($h[$i], $r[$j]);
                $addResult = $this->addProductsToResult($result, $products, $i + $j, $carry);
                $result = $addResult['result'];
                $carry = $addResult['carry'];
            }
        }

        return $result;
    }

    /**
     * 计算32位数的分解乘积
     *
     * @return array<string, int> 包含prod1, prod2, prod3, prod4的关联数组
     */
    private function calculate32BitProducts(int $h_val, int $r_val): array
    {
        // 拆分32位乘法为较小的部分
        $low16_h = $h_val & 0xFFFF;
        $high16_h = ($h_val >> 16) & 0xFFFF;
        $low16_r = $r_val & 0xFFFF;
        $high16_r = ($r_val >> 16) & 0xFFFF;

        // 实现32位乘法，避免PHP整数溢出
        return [
            'prod1' => $low16_h * $low16_r,
            'prod2' => $low16_h * $high16_r,
            'prod3' => $high16_h * $low16_r,
            'prod4' => $high16_h * $high16_r,
        ];
    }

    /**
     * 将乘积结果添加到结果数组
     *
     * @param array<int, int> $result 结果数组
     * @param array<string, int> $products 乘积数组
     * @param int $pos 位置
     * @param int $carry 进位值
     *
     * @return array{result: array<int, int>, carry: int} 包含结果数组和进位的结构
     */
    private function addProductsToResult(array $result, array $products, int $pos, int $carry): array
    {
        // 将乘积的各个部分加到适当的位置
        $sum = $result[$pos] + ($products['prod1'] & 0xFFFFFFFF) + $carry;
        $result[$pos] = $sum & 0xFFFFFFFF;
        $carry = ($sum >> 32) & 0xFFFFFFFF;

        $sum = $result[$pos + 1] + ($products['prod2'] << 16) + ($products['prod3'] << 16) + $products['prod4'] + $carry;
        $result[$pos + 1] = $sum & 0xFFFFFFFF;
        $carry = ($sum >> 32) & 0xFFFFFFFF;

        if ($carry > 0 && $pos + 2 < count($result)) {
            $result[$pos + 2] += $carry;
            $carry = 0;
        }

        return ['result' => $result, 'carry' => $carry];
    }

    /**
     * 执行模约简操作
     *
     * @param array<int, int> $result 结果数组
     *
     * @return array<int, int> 约简后的结果数组
     */
    private function performModularReduction(array $result): array
    {
        // 模P约简操作 (P = 2^130 - 5)
        // 我们知道2^130 = 5 mod P，所以我们只需要将高位乘以5并与低位相加
        if ($result[4] > 0) {
            $carry = $result[4] * 5;
            $result[0] += $carry & 0xFFFFFFFF;
            $carry >>= 32;

            if ($carry > 0) {
                $result[1] += $carry;
            }
        }

        return $result;
    }

    /**
     * 更新累加器
     *
     * @param array<int, int> $result 结果数组
     *
     * @return array<int, int> 更新后的累加器
     */
    private function updateAccumulator(array $result): array
    {
        $h = [];
        for ($i = 0; $i < 5; ++$i) {
            $h[$i] = $result[$i];
        }

        return $h;
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
        // 验证MAC长度
        if (strlen($mac) !== $this->getOutputLength()) {
            return false;
        }

        // 验证密钥长度
        if (self::KEY_LENGTH !== strlen($key)) {
            return false;
        }

        try {
            $computed = $this->compute($data, $key);

            return hash_equals($computed, $mac);
        } catch (\Throwable $e) {
            return false;
        }
    }
}
