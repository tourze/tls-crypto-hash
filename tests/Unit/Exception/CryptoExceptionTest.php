<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoHash\Tests\Unit\Exception;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoHash\Exception\CryptoException;

/**
 * 加密组件异常基类测试
 */
class CryptoExceptionTest extends TestCase
{
    /**
     * 测试异常实例化
     */
    public function testExceptionCanBeInstantiated(): void
    {
        $exception = new CryptoException('Test error message');
        
        $this->assertInstanceOf(CryptoException::class, $exception);
        $this->assertInstanceOf(\Exception::class, $exception);
        $this->assertEquals('Test error message', $exception->getMessage());
    }
    
    /**
     * 测试异常代码
     */
    public function testExceptionWithCode(): void
    {
        $exception = new CryptoException('Error', 500);
        
        $this->assertEquals(500, $exception->getCode());
    }
    
    /**
     * 测试异常链
     */
    public function testExceptionWithPrevious(): void
    {
        $previous = new \RuntimeException('Previous error');
        $exception = new CryptoException('Current error', 0, $previous);
        
        $this->assertSame($previous, $exception->getPrevious());
    }
}