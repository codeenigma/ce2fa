<?php

namespace CE2FA\Util;


/**
 * Class SpyLogger.
 *
 * Testing utility.
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
