<?php

/**
 * Filter to manipulate request in order to enforce the user to pass 2fa.
 *
 * @author Salvador Molina <salva.momo@gmail.com>
 * @package SimpleSAMLphp
 */
class sspmod_ce2fa_Auth_Process_2FA extends sspmod_ldap_Auth_Process_BaseFilter
{

	const AdminGroupSuffix = 'Admins';

	/**
	 * Initialize this filter.
	 *
	 * @param array $config Configuration information about this filter.
	 * @param mixed $reserved For future use.
	 */
	public function __construct($config, $reserved)
	{
		parent::__construct($config, $reserved);
	}

	/**
	 * Add attributes from an LDAP server.
	 *
	 * @param array &$request The current request
	 */
	public function process(&$request)
	{
		assert(is_array($request));
		assert(array_key_exists('Attributes', $request));

		$attributes =& $request['Attributes'];

		// Check if 2fa-enforcement is enabled.
		$twofa_enforcement_enabled = true;

		if (!$twofa_enforcement_enabled) {
			return;
		}

		// Get username from request.
		$username = $attributes['uid'];
		if ($this->userRequires2FA($username, $attributes) == false) {
			$request['sspmod_linotp2_Auth_Process_OTP'] = ['skip_check' => true];
		}

		return;
	}

	/**
	 * Checks if the user authenticating should be challenged with 2fa.
	 *
	 * @param string $username
	 *	The username for which to check if 2fa is needed.
	 *
	 * @return bool
	 * 	true if the user should pass 2fa, false otherwise.
	 */
	private function userRequires2FA($username, $request_attr) {
		if ($this->userIsSuperUser($request_attr)) {
			return true;
		}

		if ($this->userIsGroupAdmin($username)) {
			return true;
		}

		return false;
	}

	/**
	 * Checks if a user is considered a superuser, based on LDAP data.
	 *
	 * @param array $request_attr
	 *	The current user attributes array (from the request passed to process()).
	 * @return bool
	 * 	true if the user is a superuser, false otherwise.
	 */
	private function userIsSuperUser($request_attr) {
		return isset($request_attr['employeeType']) && ($request_attr['employeeType'] == 'superuser');
	}

	/**
	 * Checks if a user is member of any "admin" group.
	 *
	 * @param string $username
	 * 	The username of the user for which to check belonging to admin groups.
	 *
	 * @return bool
	 * 	true if the user is considered a group admin, false otherwise.
	 */
	private function userIsGroupAdmin($username) {
		$user_is_group_admin = false;

		/* @var \SimpleSAML_Auth_LDAP $ldap */
		$ldap = $this->getLdap();

		$filter = '(&(objectClass=posixGroup)(memberUid=' . $username . '))';
		try {
			$ldap_groups = $ldap->searchformultiple('ou=Groups,dc=codeenigma,dc=com', $filter, array('cn'));
		}
		catch (\Exception $e) {
			// If groups can't be retrieved, assumed user is not group admin.
			return false;
		}

		$user_groups = array();
		foreach ($ldap_groups as $key => $group_info) {
			if (is_int($key) && isset($group_info["cn"][0])) {
				$user_groups[] = $group_info["cn"][0];
			}
		}

		foreach ($user_groups as $group) {
			if (in_array($group . self::AdminGroupSuffix, $user_groups)) {
				$user_is_group_admin = true;
				break;
			}
		}

		return $user_is_group_admin;
	}

}
