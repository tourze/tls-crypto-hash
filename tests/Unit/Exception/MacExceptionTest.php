<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoHash\Tests\Unit\Exception;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoHash\Exception\MacException;
use Tourze\TLSCryptoHash\Exception\CryptoException;

/**
 * MAC异常测试
 */
class MacExceptionTest extends TestCase
{
    /**
     * 测试异常实例化
     */
    public function testExceptionCanBeInstantiated(): void
    {
        $exception = new MacException('MAC error');
        
        $this->assertInstanceOf(MacException::class, $exception);
        $this->assertInstanceOf(CryptoException::class, $exception);
        $this->assertEquals('MAC error', $exception->getMessage());
    }
    
    /**
     * 测试异常继承关系
     */
    public function testExceptionInheritance(): void
    {
        $exception = new MacException();
        
        $this->assertInstanceOf(CryptoException::class, $exception);
        $this->assertInstanceOf(\Exception::class, $exception);
    }
    
    /**
     * 测试异常链式调用
     */
    public function testExceptionChaining(): void
    {
        $root = new \Exception('Root cause');
        $middle = new CryptoException('Middle error', 0, $root);
        $exception = new MacException('MAC verification failed', 403, $middle);
        
        $this->assertEquals('MAC verification failed', $exception->getMessage());
        $this->assertEquals(403, $exception->getCode());
        $this->assertSame($middle, $exception->getPrevious());
        $this->assertSame($root, $exception->getPrevious()->getPrevious());
    }
}