<?php

use CE2FA\Auth\Ldap\Ldap;
use CE2FA\Util\SpyLogger;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\CE2FA\Auth\Process\TwoFactorSkipProcessingFilter;

/**
 * Class TwoFactorSkipProcessingFilterTest
 */
class TwoFactorSkipProcessingFilterTest extends TestCase {

  /**
   * @test
   */
  public function testConstructSkipsLdapInitIfFilterIsDisabled() {
    $config = ['proc_filter.enabled' => FALSE];
    $filter = new TwoFactorSkipProcessingFilter($config, NULL);
    $this->assertFalse($filter->filterEnabled, 'filterEnabled value correctly set.');
  }

  /**
   * @test
   */
  public function testSetLdap() {
    $filter = new TwoFactorSkipProcessingFilter([], NULL);
    $this->assertNull($filter->getLdap());
    $ldap = Ldap::fromConfigArray(['ldap.hostname' => 'test_hostname'], new SpyLogger());
    $filter->setLdap($ldap);
    $this->assertEquals($ldap, $filter->getLdap(), 'Ldap instance correctly set.');
  }

  /**
   * @test
   */
  public function testUserIsSuperUser() {
    $filter = new TwoFactorSkipProcessingFilter([], NULL);

    $this->assertFalse($filter->userIsSuperUser(['Employee Key Not Set']), 'Superuser not triggered if employeeType not set.');
    $this->assertFalse($filter->userIsSuperUser(['employeeType' => 'not superuser']), 'Superuser not triggered if employeeType is not "superuser".');
    $this->assertTrue($filter->userIsSuperUser(['employeeType' => 'superuser']), 'Superuser triggered on correct "employeeType" value.');
  }

  public function testUserIsGroupAdmin() {
    $filter = new TwoFactorSkipProcessingFilter([], NULL);

    // Prepare mock of LDAP to return desired values for positive and negative
    // scenarios (admin and non-admin).
    $ldap = $this->getMockBuilder(Ldap::class)
                 ->disableOriginalConstructor()
                 ->getMock();
    $ldap->expects($this->any())
         ->method('searchformultiple')
         ->willReturnOnConsecutiveCalls(
           [
             0 => ['cn' => [0 => 'groupnameAdmins']],
             1 => ['cn' => [0 => 'groupname']],
           ],
           [
             0 => ['cn' => [0 => 'notadmingroup']],
             1 => ['cn' => [0 => 'someothergroup']],
           ]);

    $filter->setLdap($ldap);
    $this->assertTrue($filter->userIsGroupAdmin('groupAdminUser'), 'Group Admin correctly detected.');
    $this->assertFalse($filter->userIsGroupAdmin('usernameIsIrrelevant'), 'Non Admin correctly processed.');
  }

  /**
   * @test
   */
  public function testExtractLdapAttributesFromRequestNormalizesAttributes() {
    $filter = new TwoFactorSkipProcessingFilter([], NULL);
    $attrs = [
      'cn'              => [0 => 'cnValue'],
      'gidNumber'       => [0 => 'gidNumberValue'],
      'homeDirectory'   => [0 => 'homeDirectoryValue'],
      'sn'              => [0 => 'snValue'],
      'uid'             => [0 => 'uidValue'],
      'uidNumber'       => [0 => 'uidNumberValue'],
      'displayName'     => [0 => 'displayNameValue'],
      'employeeType'    => [0 => 'employeeTypeValue'],
      'gecos'           => [0 => 'gecosValue'],
      'givenName'       => [0 => 'givenNameValue'],
      'loginShell'      => [0 => 'loginShellValue'],
      'mail'            => [0 => 'mailValue'],
      'mobile'          => [0 => 'mobileValue'],
      'telephoneNumber' => [0 => 'telephoneNumberValue'],
      'title'           => [0 => 'titleValue'],
      'userPassword'    => [0 => 'userPasswordValue'],
    ];
    $normalized = $filter->extractLdapAttributesFromRequest($attrs);

    foreach ($attrs as $key => $unnormalizedValue) {
      $this->assertEquals($unnormalizedValue[0], $normalized[$key], 'Normalized Value has expected value.');
    }

    $this->assertArrayNotHasKey('NotAnLdapAttribute', $normalized, 'Normalized array filters out undesired keys.');
  }

  /**
   * @test
   */
  public function testExtractLdapAttributesFromRequestFiltersOutUndesiredAttributes() {
    $filter = new TwoFactorSkipProcessingFilter([], NULL);
    $attrs = [
      'cn'                 => [0 => 'cnValue'],
      'NotAnLdapAttribute' => 'Ho ho ho',
    ];
    $normalized = $filter->extractLdapAttributesFromRequest($attrs);
    $this->assertArrayNotHasKey('NotAnLdapAttribute', $normalized, 'Normalized array filters out undesired keys');
  }

  /**
   * @test
   */
  public function testUserRequires2FAForNormalUser() {
    $filter = new TwoFactorSkipProcessingFilter([], NULL);
    $ldap = $this->getMockBuilder(Ldap::class)
                 ->disableOriginalConstructor()
                 ->getMock();
    $ldap->expects($this->any())
         ->method('searchformultiple')
         ->willReturn([
           0 => ['cn' => [0 => 'just one group']],
         ]);
    $filter->setLdap($ldap);
    $ldap_attr = ['uid' => 'justanormaluser', 'employeeType' => 'normal!'];
    $this->assertFalse($filter->userRequires2FA('normal-user', $ldap_attr), 'Normal user correctly handled');
  }

  /**
   * @test
   */
  public function testUserRequires2FAForSuperuser() {
    $filter = new TwoFactorSkipProcessingFilter([], NULL);
    $ldap = Ldap::fromConfigArray(['ldap.hostname' => 'dummy'], new SpyLogger());
    $filter->setLdap($ldap);
    $ldap_attr = ['uid' => 'just a superuser', 'employeeType' => 'superuser'];
    $this->assertTrue($filter->userRequires2FA('superuser', $ldap_attr), 'Superuser correctly handled');
  }

  /**
   * @test
   */
  public function testUserRequires2FAForGroupAdmin() {
    $filter = new TwoFactorSkipProcessingFilter([], NULL);

    $ldap = $this->getMockBuilder(Ldap::class)
                 ->disableOriginalConstructor()
                 ->getMock();
    $ldap->expects($this->any())
         ->method('searchformultiple')
         ->willReturn([
           0 => ['cn' => [0 => 'acme']],
           1 => ['cn' => [0 => 'acmeAdmins']],
         ]);

    $filter->setLdap($ldap);
    $this->assertTrue($filter->userRequires2FA('groupAdmin User', []), 'Group admin user correctly handled');
  }

  /**
   * @test
   */
  public function testProcessSetsRightFlagInRequestArray() {
    $filter = new TwoFactorSkipProcessingFilter([], NULL);
    $ldap = Ldap::fromConfigArray(['ldap.hostname' => 'dummy'], new SpyLogger());
    $filter->setLdap($ldap);
    $filter->filterEnabled = TRUE;

    $request_normal_u = [
      'Attributes' => ['uid' => 'someuid', 'employeeType' => 'non-superuser']
    ];
    $filter->process($request_normal_u);
    $this->assertTrue($request_normal_u['OTP']['skip_check'], 'linotp2 key correctly set for normal user.');

    $request_superuser = [
      'Attributes' => ['uid' => 'someuid', 'employeeType' => 'superuser']
    ];
    $filter->process($request_superuser);
    $this->assertArrayNotHasKey(TwoFactorSkipProcessingFilter::OTP_SKIP_FLAG, $request_superuser, 'linotp2 key not set for superuser.');
  }

}
