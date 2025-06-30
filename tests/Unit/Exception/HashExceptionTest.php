<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoHash\Tests\Unit\Exception;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoHash\Exception\HashException;
use Tourze\TLSCryptoHash\Exception\CryptoException;

/**
 * 哈希异常测试
 */
class HashExceptionTest extends TestCase
{
    /**
     * 测试异常实例化
     */
    public function testExceptionCanBeInstantiated(): void
    {
        $exception = new HashException('Hash error');
        
        $this->assertInstanceOf(HashException::class, $exception);
        $this->assertInstanceOf(CryptoException::class, $exception);
        $this->assertEquals('Hash error', $exception->getMessage());
    }
    
    /**
     * 测试异常继承关系
     */
    public function testExceptionInheritance(): void
    {
        $exception = new HashException();
        
        $this->assertInstanceOf(CryptoException::class, $exception);
        $this->assertInstanceOf(\Exception::class, $exception);
    }
    
    /**
     * 测试带参数的异常
     */
    public function testExceptionWithFullParameters(): void
    {
        $previous = new \Exception('Previous');
        $exception = new HashException('Hash failed', 100, $previous);
        
        $this->assertEquals('Hash failed', $exception->getMessage());
        $this->assertEquals(100, $exception->getCode());
        $this->assertSame($previous, $exception->getPrevious());
    }
}