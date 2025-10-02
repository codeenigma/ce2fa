# CE2FA (Code Enigma 2FA) SimpleSAMLphp module

This is an authentication module for simpleSAMLphp to alter the login flow
of SimpleSAMLPHP-linked applications at Code Enigma.

This is done by integrating with [LinOTP2](https://github.com/codeenigma/linotp2),
and injecting a specific flag in the request that allows to skip 2-Factor
Authentication when desired.

Migrated to GitLab: https://gitlab.com/code-enigma/ce2fa
