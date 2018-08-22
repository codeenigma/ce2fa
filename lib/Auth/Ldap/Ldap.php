<?php

namespace CE2FA\Auth\Ldap;

use Exception;
use SimpleSAML_Auth_LDAP;
use SimpleSAML_Error_AuthSource;
use SimpleSAML_Error_Exception;
use SimpleSAML_Error_InvalidCredential;
use SimpleSAML_Error_UserNotFound;

/**
 * Class Ldap
 */
class Ldap extends SimpleSAML_Auth_LDAP {

  protected $hostname;

  protected $port;

  protected $enable_tls;

  protected $debug;

  protected $referrals;

  protected $timeout;

  public $logger;

  public $ldap;

  /**
   * Ldap constructor.
   *
   * Overrides the default __constructor to make things testable by allowing
   * dependency injection via constructor and setter methods.
   *
   * @see parent::__construct().
   */
  public function __construct($hostname, $port, $enable_tls, $debug, $referrals, $timeout, $logger) {
    $this->hostname   = $hostname;
    $this->port       = $port;
    $this->enable_tls = $enable_tls;
    $this->debug      = $debug;
    $this->referrals  = $referrals;
    $this->timeout    = $timeout;

    $this->setLogger($logger);

    // Log the LDAP connection.
    $this->logger::debug(
      'CE2FA Process Filter Plugin ' . 'Connecting to LDAP server;' .
      ' Hostname: ' . $hostname .
      ' Port: ' . $port .
      ' Enable TLS: ' . ($enable_tls ? 'Yes' : 'No') .
      ' Debug: ' . ($debug ? 'Yes' : 'No') .
      ' Referrals: ' . ($referrals ? 'Yes' : 'No') .
      ' Timeout: ' . $timeout
    );

    if ($debug && !ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, 7)) {
      $this->logger::warning('Library - LDAP __construct(): Unable to set debug level (LDAP_OPT_DEBUG_LEVEL) to 7');
    }

    $this->setUpLdap($hostname, $port, $enable_tls, $referrals, $timeout);
  }

  /**
   * Convenience method to create an LDAPException as well as log the
   * description.
   *
   * @param string $description
   * The exception's description
   *
   * @return Exception
   */
  private function makeException($description, $type = NULL) {
    $errNo = 0x00;

    // Log LDAP code and description, if possible
    if (empty($this->ldap)) {
      $this->logger::error($description);
    }
    else {
      $errNo = @ldap_errno($this->ldap);
    }

    // Decide exception type and return
    if ($type) {
      if ($errNo !== 0) {
        // Only log real LDAP errors; not success
        $this->logger::error($description . '; cause: \'' . ldap_error($this->ldap) . '\' (0x' . dechex($errNo) . ')');
      }
      else {
        $this->logger::error($description);
      }

      switch ($type) {
        case ERR_INTERNAL:// 1 - ExInternal
          return new SimpleSAML_Error_Exception($description, $errNo);
        case ERR_NO_USER:// 2 - ExUserNotFound
          return new SimpleSAML_Error_UserNotFound($description, $errNo);
        case ERR_WRONG_PW:// 3 - ExInvalidCredential
          return new SimpleSAML_Error_InvalidCredential($description, $errNo);
        case ERR_AS_DATA_INCONSIST:// 4 - ExAsDataInconsist
          return new SimpleSAML_Error_AuthSource('ldap', $description);
        case ERR_AS_INTERNAL:// 5 - ExAsInternal
          return new SimpleSAML_Error_AuthSource('ldap', $description);
      }
    }
    else {
      if ($errNo !== 0) {
        $description .= '; cause: \'' . ldap_error($this->ldap) . '\' (0x' . dechex($errNo) . ')';
        if (@ldap_get_option($this->ldap, LDAP_OPT_DIAGNOSTIC_MESSAGE, $extendedError) && !empty($extendedError)) {
          $description .= '; additional: \'' . $extendedError . '\'';
        }
      }
      switch ($errNo) {
        case 0x20://LDAP_NO_SUCH_OBJECT
          $this->logger::warning($description);
          return new SimpleSAML_Error_UserNotFound($description, $errNo);
        case 0x31://LDAP_INVALID_CREDENTIALS
          $this->logger::info($description);
          return new SimpleSAML_Error_InvalidCredential($description, $errNo);
        case -1://NO_SERVER_CONNECTION
          $this->logger::error($description);
          return new SimpleSAML_Error_AuthSource('ldap', $description);
        default:
          $this->logger::error($description);
          return new SimpleSAML_Error_AuthSource('ldap', $description);
      }
    }
  }

  /**
   * Sets the logger.
   *
   * @param $logger
   */
  public function setLogger($logger) {
    $this->logger = $logger;
  }

  /**
   * @param array $config
   *
   * @return \CE2FA\Auth\Ldap\Ldap
   * @throws \Exception
   */
  public static function fromConfigArray($config, $logger) {
    if (!isset($config['ldap.hostname'])) {
      throw new \InvalidArgumentException('Ldap client cannot be instantiated without a hostname.');
    }

    $hostname   = $config['ldap.hostname'];
    $port       = $config['ldap.port'] ?? 389;
    $enable_tls = $config['ldap.enable_tls'] ?? FALSE;
    $debug      = $config['ldap.debug'] ?? FALSE;
    $referrals  = $config['ldap.referrals'] ?? TRUE;
    $timeout    = $config['ldap.timeout'] ?? 0;

    return new self(
      $hostname,
      $port,
      $enable_tls,
      $debug,
      $referrals,
      $timeout,
      $logger
    );
  }

  /**
   * Sets up the ldap connection.
   *
   * Originally in the __construct() function of SimpleSAML_Auth_LDAP class,
   * this is placed here for clarity.
   *
   * @param $hostname
   * @param $port
   * @param $enable_tls
   * @param $referrals
   * @param $timeout
   *
   * @throws \Exception
   */
  private function setUpLdap($hostname, $port, $enable_tls, $referrals, $timeout): void {
    // Prepare a connection for to this LDAP server. Note that this function
    // doesn't actually connect to the server.
    $this->ldap = @ldap_connect($hostname, $port);
    if ($this->ldap === FALSE) {
      throw $this->makeException('Library - LDAP __construct(): Unable to connect to \'' . $hostname . '\'', ERR_INTERNAL);
    }

    // Enable LDAP protocol version 3
    if (!@ldap_set_option($this->ldap, LDAP_OPT_PROTOCOL_VERSION, 3)) {
      throw $this->makeException('Library - LDAP __construct(): Failed to set LDAP Protocol version (LDAP_OPT_PROTOCOL_VERSION) to 3', ERR_INTERNAL);
    }

    // Set referral option
    if (!@ldap_set_option($this->ldap, LDAP_OPT_REFERRALS, $referrals)) {
      throw $this->makeException('Library - LDAP __construct(): Failed to set LDAP Referrals (LDAP_OPT_REFERRALS) to ' . $referrals, ERR_INTERNAL);
    }

    // Set timeouts, if supported
    // (OpenLDAP 2.x.x or Netscape Directory SDK x.x needed)
    $this->timeout = $timeout;
    if ($timeout > 0) {
      if (!@ldap_set_option($this->ldap, LDAP_OPT_NETWORK_TIMEOUT, $timeout)) {
        $this->logger::warning('Library - LDAP __construct(): Unable to set timeouts (LDAP_OPT_NETWORK_TIMEOUT) to ' . $timeout);
      }
      if (!@ldap_set_option($this->ldap, LDAP_OPT_TIMELIMIT, $timeout)) {
        $this->logger::warning('Library - LDAP __construct(): Unable to set timeouts (LDAP_OPT_TIMELIMIT) to ' . $timeout);
      }
    }

    // Enable TLS, if needed
    if (stripos($hostname, "ldaps:") === FALSE && $enable_tls) {
      if (!@ldap_start_tls($this->ldap)) {
        throw $this->makeException('Library - LDAP __construct(): Unable to force TLS', ERR_INTERNAL);
      }
    }
  }

}
