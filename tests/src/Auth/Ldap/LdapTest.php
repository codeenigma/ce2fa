<?php

use CE2FA\Auth\Ldap\Ldap;
use CE2FA\Util\SpyLogger;
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
    $this->assertTrue($ldap->logger::$debugCalled, 'Ldap constructor calls debug function.');
  }

}
