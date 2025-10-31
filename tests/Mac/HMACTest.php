<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoHash\Tests\Mac;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoHash\Hash\SHA256;
use Tourze\TLSCryptoHash\Hash\SHA384;
use Tourze\TLSCryptoHash\Hash\SHA512;
use Tourze\TLSCryptoHash\Mac\HMAC;

/**
 * HMAC测试类
 *
 * @internal
 */
#[CoversClass(HMAC::class)]
final class HMACTest extends TestCase
{
    /**
     * 测试HMAC-SHA256
     */
    public function testHmacSha256(): void
    {
        $hash = new SHA256();
        $hmac = new HMAC($hash);

        // 测试获取名称
        $this->assertEquals('hmac-sha256', $hmac->getName());

        // 测试获取输出长度
        $this->assertEquals($hash->getOutputLength(), $hmac->getOutputLength());

        // 测试计算和验证HMAC
        $data = 'Test Message';
        $key = 'Secret Key';

        $expected = hash_hmac('sha256', $data, $key, true);
        $computedMac = $hmac->compute($data, $key);

        $this->assertEquals($expected, $computedMac);
        $this->assertTrue($hmac->verify($data, $computedMac, $key));
        $this->assertFalse($hmac->verify('Wrong Message', $computedMac, $key));
        $this->assertFalse($hmac->verify($data, $computedMac, 'Wrong Key'));
    }

    /**
     * 测试HMAC-SHA384
     */
    public function testHmacSha384(): void
    {
        $hash = new SHA384();
        $hmac = new HMAC($hash);

        // 测试获取名称
        $this->assertEquals('hmac-sha384', $hmac->getName());

        // 测试获取输出长度
        $this->assertEquals($hash->getOutputLength(), $hmac->getOutputLength());

        // 测试计算和验证HMAC
        $data = 'Test Message';
        $key = 'Secret Key';

        $expected = hash_hmac('sha384', $data, $key, true);
        $computedMac = $hmac->compute($data, $key);

        $this->assertEquals($expected, $computedMac);
        $this->assertTrue($hmac->verify($data, $computedMac, $key));
        $this->assertFalse($hmac->verify('Wrong Message', $computedMac, $key));
        $this->assertFalse($hmac->verify($data, $computedMac, 'Wrong Key'));
    }

    /**
     * 测试HMAC-SHA512
     */
    public function testHmacSha512(): void
    {
        $hash = new SHA512();
        $hmac = new HMAC($hash);

        // 测试获取名称
        $this->assertEquals('hmac-sha512', $hmac->getName());

        // 测试获取输出长度
        $this->assertEquals($hash->getOutputLength(), $hmac->getOutputLength());

        // 测试计算和验证HMAC
        $data = 'Test Message';
        $key = 'Secret Key';

        $expected = hash_hmac('sha512', $data, $key, true);
        $computedMac = $hmac->compute($data, $key);

        $this->assertEquals($expected, $computedMac);
        $this->assertTrue($hmac->verify($data, $computedMac, $key));
        $this->assertFalse($hmac->verify('Wrong Message', $computedMac, $key));
        $this->assertFalse($hmac->verify($data, $computedMac, 'Wrong Key'));
    }

    /**
     * 测试空数据的HMAC计算
     */
    public function testEmptyDataHmac(): void
    {
        $hash = new SHA256();
        $hmac = new HMAC($hash);

        $data = '';
        $key = 'Secret Key';

        $expected = hash_hmac('sha256', $data, $key, true);
        $computedMac = $hmac->compute($data, $key);

        $this->assertEquals($expected, $computedMac);
        $this->assertTrue($hmac->verify($data, $computedMac, $key));
    }

    /**
     * 测试不同长度密钥的HMAC计算
     */
    public function testDifferentKeyLengths(): void
    {
        $hash = new SHA256();
        $hmac = new HMAC($hash);

        $data = 'Test Message';
        $keys = [
            'Short',
            'Medium Length Key',
            str_repeat('Long Key ', 10),
        ];

        foreach ($keys as $key) {
            $expected = hash_hmac('sha256', $data, $key, true);
            $computedMac = $hmac->compute($data, $key);

            $this->assertEquals($expected, $computedMac);
            $this->assertTrue($hmac->verify($data, $computedMac, $key));
        }
    }

    /**
     * 测试compute方法
     */
    public function testCompute(): void
    {
        $hash = new SHA256();
        $hmac = new HMAC($hash);

        $data = 'test data';
        $key = 'test key';

        $result = $hmac->compute($data, $key);

        $this->assertIsString($result);
        $this->assertEquals($hash->getOutputLength(), strlen($result));

        // 验证与PHP内置函数结果一致
        $expected = hash_hmac('sha256', $data, $key, true);
        $this->assertEquals($expected, $result);
    }

    /**
     * 测试verify方法
     */
    public function testVerify(): void
    {
        $hash = new SHA256();
        $hmac = new HMAC($hash);

        $data = 'test data';
        $key = 'test key';
        $mac = $hmac->compute($data, $key);

        // 正确的验证应该返回true
        $this->assertTrue($hmac->verify($data, $mac, $key));

        // 错误的数据应该返回false
        $this->assertFalse($hmac->verify('wrong data', $mac, $key));

        // 错误的MAC应该返回false
        $wrongMac = str_repeat("\x00", strlen($mac));
        $this->assertFalse($hmac->verify($data, $wrongMac, $key));

        // 错误的密钥应该返回false
        $this->assertFalse($hmac->verify($data, $mac, 'wrong key'));
    }
}
