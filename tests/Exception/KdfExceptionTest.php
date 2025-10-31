<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoHash\Tests\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use Tourze\PHPUnitBase\AbstractExceptionTestCase;
use Tourze\TLSCryptoHash\Exception\CryptoException;
use Tourze\TLSCryptoHash\Exception\KdfException;

/**
 * KDF异常测试
 *
 * @internal
 */
#[CoversClass(KdfException::class)]
final class KdfExceptionTest extends AbstractExceptionTestCase
{
    /**
     * 测试异常实例化
     */
    public function testExceptionCanBeInstantiated(): void
    {
        $exception = new KdfException('KDF error');

        $this->assertInstanceOf(KdfException::class, $exception);
        $this->assertInstanceOf(CryptoException::class, $exception);
        $this->assertEquals('KDF error', $exception->getMessage());
    }

    /**
     * 测试异常继承关系
     */
    public function testExceptionInheritance(): void
    {
        $exception = new KdfException();

        $this->assertInstanceOf(CryptoException::class, $exception);
        $this->assertInstanceOf(\Exception::class, $exception);
    }

    /**
     * 测试空消息异常
     */
    public function testExceptionWithEmptyMessage(): void
    {
        $exception = new KdfException('');

        $this->assertEquals('', $exception->getMessage());
        $this->assertEquals(0, $exception->getCode());
        $this->assertNull($exception->getPrevious());
    }
}
