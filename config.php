
<?php
/**
 * Anti-Bot Detection System Configuration
 * 
 * SINGLE FILE
 * NO ENV
 * ALL HASHES INCLUDED
 */

$BASE_SECRET = hash(
    'sha256',
    __DIR__ .
    php_uname() .
    ($_SERVER['SERVER_NAME'] ?? 'localhost') .
    'ANTIBOT_BASE_SECRET'
);

return [
    // ============================================
    // API KEYS & CREDENTIALS
    // ============================================

    'user_id' => 'omk',
    'api_key' => 'whIZWqZGblp6lUQ0A0BwQjwziNXZ5kqE',

    'proxycheck_key' => 'a7e0b3e73d4b21d37a355fb366532ff3fa935be5b8f3081cc3161a73',

    'tg_bot_token' => '8179624171:AAHWkylniIMu9jBW_P1OUnUWAD56_0czlsM',
    'tg_chat_id'   => '7101142180',

    // ============================================
    // HASHES & SALTS (ALL GENERATED HERE)
    // ============================================

    'hmac_secret' => hash('sha256', $BASE_SECRET . 'HMAC'),
    'ip_hash_salt' => hash('sha256', $BASE_SECRET . 'IP'),
    'fingerprint_salt' => hash('sha256', $BASE_SECRET . 'FINGERPRINT'),
    'session_hash_salt' => hash('sha256', $BASE_SECRET . 'SESSION'),
    'nonce_salt' => hash('sha256', $BASE_SECRET . 'NONCE'),

    // ============================================
    // DETECTION THRESHOLDS
    // ============================================

    'blacklist_threshold' => 2,
    'proxycheck_risk_threshold' => 66,

    'threshold_human_min' => 15,
    'threshold_human_max' => 25,
    'threshold_bot_min' => 50,
    'threshold_bot_max' => 65,

    // ============================================
    // BEHAVIORAL ANALYSIS WEIGHTS
    // ============================================

    'evaluation_order_randomized' => true,
    'weight_randomization' => 10, // % variance in weights
    'evaluation_windows_randomized' => true, // NEW: Randomize evaluation windows
    'window_variance' => 20, // % variance in time windows

    'mouse_analysis' => [
        'min_entropy' => 0.3,
        'curve_smoothness_max' => 0.9,
        'min_jitter_variance' => 0.1,
        'jitter_required' => true,
    ],

    'idealized_behavior' => [
        'perfect_timing_threshold' => 0.15,
        'zero_error_penalty' => 50, // Increased: humans make mistakes
        'identical_path_penalty' => 60, // Increased: humans vary
        'identical_fingerprint_penalty' => 70, // Increased: replay detection
        'no_hesitation_penalty' => 45, // NEW: humans hesitate
        'uniform_response_penalty' => 40, // NEW: humans vary responses
        'excessive_consistency_penalty' => 55, // NEW: bots are perfect
    ],

    // ============================================
    // SESSION MANAGEMENT
    // ============================================

    'session_trust_decay_rate' => 5, // % per hour
    'session_max_age' => 86400, // 24 hours

    'enforce_subnet_binding' => true,
    'enforce_tls_binding' => true, // Mandatory TLS/JA3 fingerprinting
    'enforce_ua_binding' => false,
    
    // Silent Session Aging
    'silent_aging' => [
        'enabled' => true,
        'long_session_threshold' => 7200, // 2 hours = long session
        'confidence_decay_rate' => 10, // % decay per hour for long sessions
        'auto_renew_nonce' => true, // Re-sign session with new nonce
        'delay_on_renewal_fail' => [2000, 4000], // Delay range in ms
        'reduce_quality_on_fail' => true, // Lower response quality
        'no_captcha_on_aging' => true, // Never show CAPTCHA for aging
    ],

    // ============================================
    // SHADOW ENFORCEMENT
    // ============================================

    'shadow_mode' => 'shadow', // 'monitor', 'shadow', or 'block'

    'shadow_tactics' => [
        'silent_rate_limit' => true,
        'response_delay_min' => 2000,
        'response_delay_max' => 5000,
        'fake_success_responses' => true,
        'perpetual_loading' => true,
        'meaningless_responses' => true, // Correct-looking but useless data
        'non_uniform_delays' => true, // Vary delays to prevent learning
        'light_throttling' => true, // Gradual slowdown
        'poison_ml' => true, // Poison machine learning training data
        'no_phantom_pages' => true, // Never use fake elements (per requirements)
    ],

    'shadow_rate_limit' => 10,
    'shadow_rate_window' => 60,
    'shadow_block_duration' => 300,

    // ============================================
    // STEALTH BOT DETECTION
    // ============================================

    'stealth_detection' => [
        'check_playwright_stealth' => true,
        'check_puppeteer_stealth' => true,
        'check_selenium_stealth' => true,
        'check_chrome_headless_new' => true,
        'check_navigator_properties' => true,
        'check_webdriver_flags' => true,
        'check_cdp_indicators' => true,
        'check_webgl_fingerprint' => true,
        'check_canvas_fingerprint' => true,
        'check_audio_fingerprint' => true,
    ],

    'tls_fingerprinting' => [
        'enabled' => true,
        'enforce_ja3_match' => true,
        'ja3_mismatch_penalty' => 100,
        'track_cipher_suites' => true,
        'track_header_order' => true,
        'terminate_on_change' => true, // Silent termination on JA3 change
        'track_cumulative_reuse' => true, // Track JA3 reuse across sessions
        'cumulative_reuse_threshold' => 10, // Flag after 10+ sessions with same JA3
    ],

    // ============================================
    // LOGGING & MONITORING
    // ============================================

    'log_file' => __DIR__ . '/logs/antibot.log',
    'security_log_file' => __DIR__ . '/logs/security.log',

    'logging' => [
        'hash_fingerprints' => false,
        'hide_rejection_reasons' => false,
        'hide_raw_scores' => false,
        'separate_security_logs' => true,
    ],

    'silent_scoring_enabled' => false,

    // ============================================
    // REPLAY ATTACK PREVENTION
    // ============================================

    'nonce_expiry' => 300,
    'nonce_cleanup_interval' => 3600,
    'hmac_algorithm' => 'sha256',

    // ============================================
    // BEHAVIORAL ENTROPY REQUIREMENTS
    // ============================================

    'min_timing_entropy' => 0.2,
    'min_navigation_entropy' => 0.3,
    'min_interaction_entropy' => 0.25,
    
    // Entropy Memory (Time-Based Cross-Session Analysis)
    'entropy_memory' => [
        'enabled' => true,
        'store_timing_variance' => true,
        'store_deviation_per_fingerprint' => true,
        'compare_across_sessions' => true,
        'consistency_threshold' => 0.1, // CV < 0.1 = automation
        'min_sessions_for_comparison' => 2,
        'variance_penalty' => 45, // Penalty for low variance
    ],

    'drift_detection' => [
        'enabled' => true,
        'max_pattern_similarity' => 0.7,
        'min_sessions_for_drift' => 3,
        'drift_penalty' => 40,
    ],

    // ============================================
    // PERIODIC VERIFICATION
    // ============================================

    'periodic_verification' => [
        'enabled' => true,
        'interval_hours' => 4,
        'ml_bot_detection' => true,
        'long_session_threshold' => 7200,
    ],
];
