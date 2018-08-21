<?php

namespace SimpleSAML\Module\CE2FA\Auth\Process;

use CE2FA\Auth\Ldap\Ldap;
use SimpleSAML_Auth_ProcessingFilter;

/**
 * Filter to manipulate request in order to enforce the user to pass 2fa.
 *
 * @author Salvador Molina <salva.momo@gmail.com>
 * @package SimpleSAMLphp
 */
class TwoFactorSkipProcessingFilter extends SimpleSAML_Auth_ProcessingFilter {

  const AdminGroupSuffix = 'Admins';

  /**
   * @var \CE2FA\Auth\Ldap\Ldap
   */
  private $ldap;

  /**
   * @var boolean
   */
  private $filterEnabled;

  /**
   * 2FA constructor.
   *
   * @param array $config The configuration of this authproc.
   * @param mixed $reserved
   *
   * @throws \Exception
   */
  public function __construct($config, $reserved) {
    parent::__construct($config, $reserved);

    $cfg                 = \SimpleSAML_Configuration::loadFromArray($config, 'ce2fa:2FA');
    $this->filterEnabled = $cfg->getBoolean('proc_filter.enabled');
    $this->initLdap($cfg);
  }

  /**
   * @param \SimpleSAML_Configuration $config
   *
   * @throws \Exception
   */
  private function initLdap(\SimpleSAML_Configuration $config) {
    $this->ldap = Ldap::fromConfig($config);
  }

  /**
   * Add attributes from an LDAP server.
   *
   * @param array &$request The current request
   */
  public function process(&$request) {
    assert(is_array($request));
    assert(array_key_exists('Attributes', $request));

    if ($this->filterEnabled) {
      $ldap_attributes = $this->extractLdapAttributesFromRequest($request['Attributes']);
      $username = $ldap_attributes['uid'];

      if ($this->userRequires2FA($username, $ldap_attributes) === FALSE) {
        $request['sspmod_linotp2_Auth_Process_OTP'] = [
          'skip_check' => TRUE,
        ];
      }
    }

    return;
  }

  /**
   * Checks if the user authenticating should be challenged with 2fa.
   *
   * @param string $username
   *  The username for which to check if 2fa is needed.
   * @param array $ldap_attributes
   *  Array of normalized LDAP Attributes
   *
   * @return bool
   *  true if the user should pass 2fa, false otherwise.
   */
  private function userRequires2FA($username, $ldap_attributes) {
    if ($this->userIsSuperUser($ldap_attributes)) {
      return TRUE;
    }

    if ($this->userIsGroupAdmin($username)) {
      return TRUE;
    }

    return FALSE;
  }

  /**
   * Checks if a user is considered a superuser, based on LDAP data.
   *
   * @param array $ldap_attributes
   *  A normalized array of the user's LDAP attributes
   *
   * @return bool
   *  true if the user is a superuser, false otherwise.
   */
  private function userIsSuperUser($ldap_attributes) {
    return isset($ldap_attributes['employeeType']) && ($ldap_attributes['employeeType'] === 'superuser');
  }

  /**
   * Checks if a user is member of any "admin" group.
   *
   * @param string $username
   *  The username of the user for which to check belonging to admin groups.
   *
   * @return bool
   *  true if the user is considered a group admin, false otherwise.
   */
  private function userIsGroupAdmin($username) {
    $user_is_group_admin = FALSE;

    $filter = '(&(objectClass=posixGroup)(memberUid=' . $username . '))';
    try {
      $ldap_groups = $this->ldap->searchformultiple('ou=Groups,dc=codeenigma,dc=com', $filter, ['cn']);
    } catch (\Exception $e) {
      // If groups can't be retrieved, assume user is not group admin.
      return FALSE;
    }

    $user_groups = [];
    foreach ($ldap_groups as $key => $group_info) {
      if (is_int($key) && isset($group_info["cn"][0])) {
        $user_groups[] = $group_info["cn"][0];
      }
    }

    foreach ($user_groups as $group) {
      if (in_array($group . self::AdminGroupSuffix, $user_groups)) {
        $user_is_group_admin = TRUE;
        break;
      }
    }

    return $user_is_group_admin;
  }

  /**
   * Normalizes LDAP attributes from the request array into a plain array.
   *
   * @param array $attributes
   *
   * @return array
   */
  private function extractLdapAttributesFromRequest($attributes) {
    // Not including objectClass items. Don't need them.
    $ldap_attributes = [
      'cn',
      'gidNumber',
      'homeDirectory',
      'sn',
      'uid',
      'uidNumber',
      'displayName',
      'employeeType',
      'gecos',
      'givenName',
      'loginShell',
      'mail',
      'mobile',
      'telephoneNumber',
      'title',
      'userPassword',
    ];

    $normalized = [];
    foreach ($ldap_attributes as $attribute) {
      if (isset($attributes[$attribute])) {
        $normalized[$attribute] = is_array($attributes[$attribute])
          ? $attributes[$attribute][0]
          : $attributes[$attribute];
      }
    }

    return $normalized;
  }

}
