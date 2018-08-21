<?php

namespace CE2FA\Auth\Ldap;

use SimpleSAML\Logger;
use SimpleSAML_Auth_LDAP;
use SimpleSAML_Configuration;


/**
 * Class Ldap
 */
class Ldap {

  private $hostname;

  private $port;

  private $enable_tls;

  private $debug;

  private $referrals;

  private $timeout;

  private $username;

  private $password;

  /**
   * Ldap constructor.
   */
  private function __construct($hostname, $port, $enable_tls, $debug, $referrals, $timeout, $username, $password) {
    $this->hostname   = $hostname;
    $this->port       = $port;
    $this->enable_tls = $enable_tls;
    $this->debug      = $debug;
    $this->referrals  = $referrals;
    $this->timeout    = $timeout;
    $this->username   = $username;
    $this->password   = $password;

    // Log the LDAP connection
    Logger::debug(
      'CE2FA Process Filter Plugin ' . 'Connecting to LDAP server;' .
      ' Hostname: ' . $hostname .
      ' Port: ' . $port .
      ' Enable TLS: ' . ($enable_tls ? 'Yes' : 'No') .
      ' Debug: ' . ($debug ? 'Yes' : 'No') .
      ' Referrals: ' . ($referrals ? 'Yes' : 'No') .
      ' Timeout: ' . $timeout .
      ' Username: ' . $username .
      ' Password: ' . (empty($password) ? '' : '********')
    );

    $this->client = new SimpleSAML_Auth_LDAP($hostname, $enable_tls, $debug, $timeout, $port, $referrals);
    if ($this->username && $this->password) {
      $this->client->bind($this->username, $this->password);
    }
  }

  /**
   * @param \SimpleSAML_Configuration $config
   *
   * @return \SimpleSAML\Module\CE2FA\Auth\Ldap\Ldap
   * @throws \Exception
   */
  public static function fromConfig(SimpleSAML_Configuration $config) {
    //    $expected = [
    //      'ldap.hostname',
    //      'ldap.port',
    //      'ldap.enable_tls',
    //      'ldap.debug',
    //      'ldap.referrals',
    //      'ldap.timeout',
    //      'ldap.username',
    //      'ldap.password',
    //    ];

    return new self(
      $config->getString('ldap.hostname'),
      $config->getInteger('ldap.port', 389),
      $config->getBoolean('ldap.enable_tls', FALSE),
      $config->getBoolean('ldap.debug', FALSE),
      $config->getBoolean('ldap.referrals', TRUE),
      $config->getInteger('ldap.timeout', 0),
      $config->getString('ldap.username', NULL),
      $config->getString('ldap.password', NULL)
    );
  }

  /**
   * @see SimpleSAML_Auth_LDAP::searchformultiple().
   *
   * @throws \Exception
   */
  public function searchformultiple($bases, $filters, $attributes = [], $and = TRUE, $escape = TRUE) {
    return $this->client->searchformultiple($bases, $filters, $attributes, $and, $escape);
  }

}
