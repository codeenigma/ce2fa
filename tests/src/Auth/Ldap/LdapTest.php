<?php

use CE2FA\Auth\Ldap\Ldap;
use PHPUnit\Framework\TestCase;

/**
 * Class LdapTest
 */
class LdapTest extends TestCase {

  /**
   * @expectedException \InvalidArgumentException
   * @expectedExceptionMessage Ldap client cannot be instantiated without a
   *   hostname.
   */
  public function testFromConfigArrayFailsIfHostnameIsNotPresent() {
    $config = ['some_value' => 1];
    Ldap::fromConfigArray($config, new SpyLogger());
  }

  /**
   * @test
   */
  public function testFromConfigArray() {
    $config = [
      'ldap.hostname' => 'ldaps://ldap-endpoint.com',
    ];

    $logger = new SpyLogger();
    $ldap = Ldap::fromConfigArray($config, $logger);
    $this->assertInstanceOf(SpyLogger::class, $ldap->logger);
    $this->assertTrue($ldap->logger::$debugCalled);
  }

}

/**
 * Class FakeLogger
 */
class SpyLogger {

  public static $debugCalled;

  public static function debug($string) {
    self::$debugCalled = TRUE;
    return;
  }

  public static function warning($string) {}

  public static function error($string) {}

  public static function info($string) {}

}
