<?php

declare(strict_types=1);

namespace Edoardoagnelli1357\LaravelWaf\Support;

use BadMethodCallException;
use Detection\MobileDetect;
use Jaybizzle\CrawlerDetect\CrawlerDetect;

/**
 * WAF-oriented user agent & device detector.
 *
 * - Uses CrawlerDetect and Mobile_Detect when available (soft dependency).
 * - Provides fallback regex-based detection.
 * - Adds WAF-specific helpers: device type, robot detection, UA spoofing hints, match scoring.
 */
class Agent
{
    public const DETECTION_TYPE_BASIC = 0;

    public const DETECTION_TYPE_EXTENDED = 1;

    public const VERSION_TYPE_STRING = 0;

    public const VERSION_TYPE_FLOAT = 1;

    public const VER = '([0-9]+(?:\.[0-9]+)*)';

    /** @var array Minimal list of phone devices (extend as needed) */
    protected static $phoneDevices = [
        'iPhone' => 'iPhone',
        'Android' => 'Android',
        'Windows Phone' => 'Windows Phone',
        'BlackBerry' => 'BlackBerry',
    ];

    /** @var array Minimal tablet devices */
    protected static $tabletDevices = [
        'iPad' => 'iPad',
        'Android Tablet' => 'Android(?!.*Mobile)',
    ];

    /** @var array Base operating systems */
    protected static $operatingSystems = [
        'Windows' => 'Windows',
        'Mac OS X' => 'Macintosh|Mac OS X',
        'Linux' => 'Linux',
        'Android' => 'Android',
        'iOS' => 'iPhone|iPad',
    ];

    /** @var array Base browsers */
    protected static $browsers = [
        'Chrome' => 'Chrome/(?:'.self::VER.')',
        'Firefox' => 'Firefox/(?:'.self::VER.')',
        'Safari' => 'Version/(?:'.self::VER.').*Safari',
        'Edge' => 'Edge/(?:'.self::VER.')|Edg/(?:'.self::VER.')',
        'IE' => 'MSIE (?:'.self::VER.')|Trident/.*rv:(?:'.self::VER.')',
    ];

    /** @var array Additional WAF-oriented rules (extend) */
    protected static $additionalBrowsers = [
        'BotBrowser' => 'HeadlessChrome|PhantomJS|Puppeteer',
        'curl' => 'curl\/'.self::VER,
        'wget' => 'Wget\/'.self::VER,
    ];

    /** @var array Additional properties for version extraction */
    protected static $additionalProperties = [
        'Chrome' => 'Chrome/[VER]',
        'Firefox' => 'Firefox/[VER]',
        'Safari' => 'Version/[VER]',
    ];

    /** @var array Utilities / special UA patterns */
    protected static $utilities = [
        'Micromessenger' => 'MicroMessenger',
        'Amazon CloudFront' => 'Amazon CloudFront',
    ];

    /** @var string|null last provided user agent */
    protected $userAgent;

    /** @var array last regex matches for internal usage */
    protected $matchesArray = [];

    /** @var int detection type (basic|extended) */
    protected $detectionType = self::DETECTION_TYPE_EXTENDED;

    /** @var CrawlerDetect|null */
    protected static $crawlerDetect;

    /** @var Mobile_Detect|null */
    protected static $mobileDetect;

    /**
     * Agent constructor.
     *
     * @param  string|null  $userAgent  pass UA string (optional). If null, uses HTTP headers.
     */
    public function __construct(?string $userAgent = null)
    {
        $this->userAgent = $userAgent ?? $this->getUserAgent();
    }

    /**
     * Returns or constructs CrawlerDetect instance.
     */
    public function getCrawlerDetect(): CrawlerDetect
    {
        if (static::$crawlerDetect === null) {
            if (class_exists(CrawlerDetect::class)) {
                static::$crawlerDetect = new CrawlerDetect;
            } else {
                // lightweight fallback: a minimal detector using a few patterns
                static::$crawlerDetect = new CrawlerDetect(['Crawler' => ['Googlebot', 'Bingbot', 'Slurp', 'DuckDuckBot', 'Baiduspider', 'YandexBot']]);
            }
        }

        return static::$crawlerDetect;
    }

    /**
     * Returns/constructs Mobile_Detect instance if available.
     */
    public function getMobileDetect(): ?MobileDetect
    {
        if (static::$mobileDetect === null) {
            if (class_exists(MobileDetect::class)) {
                static::$mobileDetect = new MobileDetect;
            } else {
                static::$mobileDetect = null;
            }
        }

        return static::$mobileDetect;
    }

    /**
     * Get HTTP user agent from server environment.
     */
    public function getUserAgent(): string
    {
        if (! empty($this->userAgent)) {
            return $this->userAgent;
        }

        $ua = $this->getHttpHeader('HTTP_USER_AGENT') ?? $this->getHttpHeader('User-Agent') ?? '';

        return (string) $ua;
    }

    /**
     * Generic server header getter (works with $_SERVER).
     */
    public function getHttpHeader(string $key)
    {
        $key = strtoupper($key);
        if (strpos($key, 'HTTP_') !== 0 && strpos($key, 'USER-AGENT') === false) {
            // allow 'User-Agent' fallback
            $key = 'HTTP_'.str_replace('-', '_', $key);
        }

        return $_SERVER[$key] ?? $_SERVER[str_replace('-', '_', $key)] ?? null;
    }

    /**
     * Get Cloudflare headers (if present).
     */
    public function getCfHeaders(): array
    {
        $headers = [];
        foreach ($_SERVER as $k => $v) {
            if (stripos($k, 'HTTP_CLOUDFRONT_') === 0 || stripos($k, 'CLOUDFRONT_') === 0) {
                $headers[$k] = $v;
            }
        }

        return $headers;
    }

    /**
     * Set detection type.
     */
    public function setDetectionType(int $type): void
    {
        $this->detectionType = $type;
    }

    /**
     * Basic match helper. Accepts regex string(s) (pipe-separated or array).
     *
     * @param  string|array  $regex
     */
    public function match($regex, ?string $userAgent = null): bool
    {
        $ua = $userAgent ?? $this->getUserAgent();
        $this->matchesArray = [];

        if (empty($ua)) {
            return false;
        }

        // Normalize regex list
        $patterns = [];
        if (is_array($regex)) {
            foreach ($regex as $r) {
                $patterns[] = $r;
            }
        } else {
            // If pattern contains '|' and no delimiters, split; else treat as single pattern
            $patterns = preg_split('/\s*\|\s*/', $regex);
        }

        foreach ($patterns as $pattern) {
            $pattern = (string) $pattern;
            if ($pattern === '') {
                continue;
            }

            // If pattern already includes a delimiter, use it; otherwise wrap with #...#i
            $use = $pattern;

            // if user provided a raw regex with parentheses or slashes we try to reuse it
            if (@preg_match($pattern, '') === false) {
                $use = sprintf('#%s#is', str_replace('#', '\#', $pattern));
            }

            if (@preg_match($use, $ua, $matches)) {
                $this->matchesArray = $matches;

                return true;
            }
        }

        return false;
    }

    /**
     * Match a UA against a key (e.g., 'Chrome' or 'iPhone') using detection rules.
     */
    protected function matchUAAgainstKey(string $key): bool
    {
        $rules = $this->detectionType === self::DETECTION_TYPE_EXTENDED
            ? static::getDetectionRulesExtended()
            : static::getMobileDetectionRules();

        // If key exists as-is
        if (isset($rules[$key]) && $this->match($rules[$key])) {
            return true;
        }

        // try case-insensitive partial match
        foreach ($rules as $k => $regex) {
            if (strcasecmp($k, $key) === 0) {
                if ($this->match($regex)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Find detection rules against UA and return matched key.
     *
     * @return string|false
     */
    protected function findDetectionRulesAgainstUA(array $rules, ?string $userAgent = null)
    {
        foreach ($rules as $key => $regex) {
            if (empty($regex)) {
                continue;
            }

            if ($this->match($regex, $userAgent)) {
                return $key ?: (isset($this->matchesArray[0]) ? $this->matchesArray[0] : false);
            }
        }

        return false;
    }

    /**
     * Return merged detection rules (desktop + phone + tablet + OS + browsers + utilities)
     */
    public static function getDetectionRulesExtended(): array
    {
        static $rules;

        if (! $rules) {
            $rules = static::mergeRules(
                static::$operatingSystems,
                static::$phoneDevices,
                static::$tabletDevices,
                static::$browsers,
                static::$additionalBrowsers,
                static::$additionalProperties,
                static::$utilities
            );
        }

        return $rules;
    }

    /**
     * Minimal mobile detection rules used in basic mode.
     */
    public static function getMobileDetectionRules(): array
    {
        return static::mergeRules(
            static::$phoneDevices,
            static::$tabletDevices
        );
    }

    /**
     * Merge multiple rule arrays.
     *
     * @param  array  ...$all
     */
    protected static function mergeRules(...$all): array
    {
        $merged = [];

        foreach ($all as $rules) {
            foreach ($rules as $key => $value) {
                if (! isset($merged[$key])) {
                    $merged[$key] = $value;
                } elseif (is_array($merged[$key])) {
                    $merged[$key][] = $value;
                } else {
                    $merged[$key] .= '|'.$value;
                }
            }
        }

        return $merged;
    }

    /**
     * Get browser name or false.
     */
    public function browser(?string $userAgent = null)
    {
        return $this->findDetectionRulesAgainstUA(static::getBrowsers(), $userAgent);
    }

    /**
     * Get platforms (OS) name or false.
     */
    public function platform(?string $userAgent = null)
    {
        return $this->findDetectionRulesAgainstUA(static::getPlatforms(), $userAgent);
    }

    /**
     * Get device (phone/tablet/desktop/utility) name or false.
     */
    public function device(?string $userAgent = null)
    {
        $rules = static::mergeRules(
            static::getDesktopDevices(),
            static::getPhoneDevices(),
            static::getTabletDevices(),
            static::getUtilities()
        );

        return $this->findDetectionRulesAgainstUA($rules, $userAgent);
    }

    /**
     * Return array of known browsers (merged).
     */
    public static function getBrowsers(): array
    {
        return static::mergeRules(static::$additionalBrowsers, static::$browsers);
    }

    /**
     * Return array of known operating systems.
     */
    public static function getOperatingSystems(): array
    {
        return static::mergeRules(static::$operatingSystems);
    }

    /**
     * Return platforms mapping (alias for OS).
     */
    public static function getPlatforms(): array
    {
        return static::getOperatingSystems();
    }

    /**
     * Return desktop devices (small set).
     */
    public static function getDesktopDevices(): array
    {
        return [
            'Desktop' => 'Windows|Macintosh|Linux|CrOS',
        ];
    }

    /**
     * Accessors for phone/tablet/utilities (can be extended).
     */
    public static function getPhoneDevices(): array
    {
        return static::$phoneDevices;
    }

    public static function getTabletDevices(): array
    {
        return static::$tabletDevices;
    }

    public static function getUtilities(): array
    {
        return static::$utilities;
    }

    /**
     * Return properties (merged).
     */
    public static function getProperties(): array
    {
        return static::mergeRules(static::$additionalProperties);
    }

    /**
     * Detect if UA belongs to a robot/crawler.
     */
    public function isRobot(?string $userAgent = null): bool
    {
        $ua = $userAgent ?? $this->getUserAgent();

        // Prefer CrawlerDetect if available
        try {
            return $this->getCrawlerDetect()->isCrawler($ua);
        } catch (\Throwable $e) {
            // fallback minimal check
            return (bool) preg_match('/(bot|crawl|spider|slurp|bing|baidu|yandex)/i', $ua);
        }
    }

    /**
     * Detect mobile devices (phone).
     */
    public function isMobile(?string $userAgent = null, ?array $httpHeaders = null): bool
    {
        $ua = $userAgent ?? $this->getUserAgent();

        // Cloudfront override check
        if ($this->getUserAgent() === 'Amazon CloudFront') {
            $cf = $this->getCfHeaders();
            if (array_key_exists('HTTP_CLOUDFRONT_IS_MOBILE_VIEWER', $cf)) {
                return $cf['HTTP_CLOUDFRONT_IS_MOBILE_VIEWER'] === 'true';
            }
        }

        $md = $this->getMobileDetect();
        if ($md instanceof MobileDetect) {
            return $md->isMobile() && ! $md->isTablet();
        }

        // fallback to regex
        return (bool) preg_match('/(iPhone|Android.+Mobile|Windows Phone|BlackBerry)/i', $ua);
    }

    /**
     * Detect tablets.
     */
    public function isTablet(?string $userAgent = null, ?array $httpHeaders = null): bool
    {
        $ua = $userAgent ?? $this->getUserAgent();

        $md = $this->getMobileDetect();
        if ($md instanceof MobileDetect) {
            return $md->isTablet();
        }

        return (bool) preg_match('/(iPad|Android(?!.*Mobile)|Tablet)/i', $ua);
    }

    /**
     * High-level device type: desktop|phone|tablet|robot|other
     */
    public function deviceType(?string $userAgent = null, ?array $httpHeaders = null): string
    {
        if ($this->isRobot($userAgent)) {
            return 'robot';
        }

        if ($this->isTablet($userAgent, $httpHeaders)) {
            return 'tablet';
        }

        if ($this->isMobile($userAgent, $httpHeaders)) {
            return 'phone';
        }

        return 'desktop';
    }

    /**
     * Extract a version for a named property (Chrome, Firefox, etc).
     */
    public function version(string $propertyName, int $type = self::VERSION_TYPE_STRING)
    {
        if ($propertyName === '') {
            return false;
        }

        $properties = self::getProperties();

        if (! isset($properties[$propertyName])) {
            return false;
        }

        $rules = (array) $properties[$propertyName];

        foreach ($rules as $rule) {
            $pattern = str_replace('[VER]', self::VER, $rule);
            if (preg_match('#'.$pattern.'#is', $this->getUserAgent(), $m) && ! empty($m[1])) {
                return ($type === self::VERSION_TYPE_FLOAT) ? (float) $m[1] : $m[1];
            }
        }

        return false;
    }

    /**
     * Returns languages from Accept-Language header (ordered).
     */
    public function languages(?string $acceptLanguage = null): array
    {
        if ($acceptLanguage === null) {
            $acceptLanguage = $this->getHttpHeader('HTTP_ACCEPT_LANGUAGE') ?? $this->getHttpHeader('Accept-Language');
        }

        if (! $acceptLanguage) {
            return [];
        }

        $languages = [];
        foreach (explode(',', $acceptLanguage) as $piece) {
            $parts = explode(';', trim($piece));
            $lang = strtolower($parts[0]);
            $q = 1.0;
            if (isset($parts[1]) && strpos($parts[1], 'q=') !== false) {
                $q = (float) str_replace('q=', '', $parts[1]);
            }
            $languages[$lang] = $q;
        }

        arsort($languages);

        return array_keys($languages);
    }

    /**
     * WAF-centric quick suspicion score:
     * - robot: +30
     * - headless/curl/wget in UA: +30
     * - impossible UA (no spaces / single token): +20
     * - spoofed UA hints (mismatch between headers): +10
     *
     * Score range: 0..100
     */
    public function suspicionScore(): int
    {
        $score = 0;
        $ua = $this->getUserAgent();

        if ($this->isRobot($ua)) {
            $score += 30;
        }

        // headless / common bot clients
        if ($this->match('HeadlessChrome|PhantomJS|Puppeteer|curl\/|Wget\/', $ua)) {
            $score += 30;
        }

        // trivial UA (single token or empty)
        if (preg_match('/^[^\s]{1,50}$/', $ua)) {
            $score += 20;
        }

        // header mismatch heuristic: Accept-Language exists for browsers but not for many bots
        $acceptLang = $this->getHttpHeader('HTTP_ACCEPT_LANGUAGE') ?? '';
        if ($this->isMobile($ua) && empty($acceptLang)) {
            $score += 10;
        }

        return min(100, $score);
    }

    /**
     * Magic helper to handle `isSomething()` dynamic calls.
     *
     * Examples:
     *   $agent->isMobile()
     *   $agent->isChrome()
     */
    public function __call($name, $arguments)
    {
        if (strpos($name, 'is') !== 0) {
            throw new BadMethodCallException("No such method: {$name}");
        }

        $key = substr($name, 2); // e.g., Chrome, Mobile, Tablet, Robot, iPhone

        // normalize: treat isMobile/isTablet/isRobot specially
        $lc = strtolower($key);
        if ($lc === 'mobile' || $lc === 'phone') {
            return $this->isMobile(...$arguments);
        }
        if ($lc === 'tablet') {
            return $this->isTablet(...$arguments);
        }
        if ($lc === 'robot') {
            return $this->isRobot(...$arguments);
        }

        // Otherwise try to match against detection rules
        $this->setDetectionType(self::DETECTION_TYPE_EXTENDED);

        return $this->matchUAAgainstKey($key);
    }
}
