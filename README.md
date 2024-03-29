# CE2FA (Code Enigma 2FA) SimpleSAMLphp module

This is an authentication module for simpleSAMLphp to alter the login flow
of SimpleSAMLPHP-linked applications at Code Enigma.

This is done by integrating with [LinOTP2](https://github.com/codeenigma/linotp2),
and injecting a specific flag in the request that allows to skip 2-Factor
Authentication when desired.

At the moment, the logic allows to skip 2FA for normal users in the CE's LDAP,
while enforcing 2FA for users considered "Group Administrators" or "Superusers".

```
  $request[SimpleSAML\Module\CE2FA\Auth\Process\TwoFactorSkipProcessingFilter::OTP_SKIP_FLAG] = [
    'skip_check' => TRUE,
  ];
```

## Installation

If you installed SimpleSAMLphp using composer, you may simply add this to your root `composer.json` file:

```
    "repositories": [
        {
            "url": "git@github.com:codeenigma/ce2fa.git",
            "type": "git"
        }
    ],
```

Then run `composer require codeenigma/simplesamlphp-module-ce2fa dev-master`.

## Configuration

Edit the desired SimpleSAMLPHP Entity ID metadata, in saml20-sp-remote.php,
and add the following settings array as instructed by SimpleSAML:

```
    'class' => 'ce2fa:TwoFactorSkipProcessingFilter',
    'proc_filter.enabled' => TRUE,
    'ldap.hostname' => 'ldaps://your-ldap-endpoint',
    'ldap.enable_tls' => TRUE,
    'ldap.debug' => FALSE,
    'ldap.timeout' => 0,
    'ldap.port' => 636,
    'ldap.referrals' => TRUE,
    'ldap.username' => NULL, // dn to perform the search of user groups.
    'ldap.password' => NULL,
```

`'proc_filter.enabled'`: Set to FALSE if you want to leave the configuration
in place but disable the filter temporarily.

`'ldap.username'`: Not really needed for the moment.

`'ldap.password'`: Not really needed for the moment.

## Running tests

Run `composer` install inside the module repository.

From within the repository root, execute phpunit against the tests folder:

```
./vendor/bin/phpunit tests/
```

SimpleSAMLphp before 1.15 used to perform some assert() calls that are 
deprecated and make phpunit fail. For such reason, `~1.15-dev` version of
SimpleSAMLphp is required as a dev dependency. Executing tests with older
versions could make them fail. 