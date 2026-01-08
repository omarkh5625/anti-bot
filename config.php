<?php
/**
 * Anti-Bot Detection System Configuration
 * 
 * SECURITY NOTICE:
 * - Change all default values before deploying to production
 * - Keep this file secure and outside public web root if possible
 * - Never commit sensitive API keys to version control
 */

return [
    // ============================================
    // API KEYS & CREDENTIALS
    // ============================================
    
    // Neutrino API for IP reputation checking
    'user_id' => '',  // Your Neutrino user ID
    'api_key' => '',  // Your Neutrino API key
    
    // ProxyCheck.io API for proxy/VPN detection
    'proxycheck_key' => '',  // Your ProxyCheck.io API key
    
    // Telegram notifications (optional)
    'tg_bot_token' => '',  // Your Telegram bot token
    'tg_chat_id' => '',    // Your Telegram chat ID
    
    // ============================================
    // FINGERPRINT SECURITY
    // ============================================
    
    // Secret salt for fingerprinting (MUST be unique per installation)
    // Generate with: openssl rand -hex 32
    // WARNING: This default is INSECURE - generate a new one immediately!
    'fingerprint_salt' => getenv('ANTIBOT_SALT') ?: bin2hex(random_bytes(32)),  // Auto-generate secure random salt
    
    // ============================================
    // DETECTION THRESHOLDS
    // ============================================
    
    // IP reputation thresholds
    'blacklist_threshold' => 2,           // Number of blacklists before blocking
    'proxycheck_risk_threshold' => 66,    // Risk score threshold (0-100)
    
    // Bot detection thresholds (randomized at runtime)
    'threshold_human_min' => 15,          // Minimum threshold for confident human
    'threshold_human_max' => 25,          // Maximum threshold for confident human
    'threshold_bot_min' => 50,            // Minimum threshold for likely bot
    'threshold_bot_max' => 65,            // Maximum threshold for likely bot
    
    // ============================================
    // BEHAVIORAL ANALYSIS WEIGHTS
    // ============================================
    
    // Enable randomization to prevent reverse engineering
    'evaluation_order_randomized' => true,
    'weight_randomization' => 10,  // Percentage variance in weights (0-20)
    
    // Mouse movement analysis thresholds
    'mouse_analysis' => [
        'min_entropy' => 0.3,              // Minimum entropy for human-like randomness
        'curve_smoothness_max' => 0.9,     // Maximum smoothness (too smooth = bot)
        'min_jitter_variance' => 0.1,      // Minimum jitter for natural hand tremor
        'jitter_required' => true,         // Require jitter for human classification
    ],
    
    // Idealized behavior detection (perfect = bot)
    'idealized_behavior' => [
        'perfect_timing_threshold' => 0.15,        // CV below this = too perfect
        'zero_error_penalty' => 40,                // Penalty for zero errors
        'identical_path_penalty' => 50,            // Penalty for identical navigation
        'identical_fingerprint_penalty' => 60,     // Penalty for fingerprint reuse
    ],
    
    // ============================================
    // SESSION MANAGEMENT
    // ============================================
    
    // Session trust decay
    'session_trust_decay_rate' => 5,      // Percentage decay per hour
    'session_max_age' => 86400,           // Maximum session age (24 hours)
    
    // Session binding enforcement levels
    'enforce_subnet_binding' => true,     // Require same IP subnet
    'enforce_tls_binding' => false,       // Require same TLS fingerprint (may vary per request)
    'enforce_ua_binding' => false,        // Require same user-agent hash (allow UA changes)
    
    // ============================================
    // SHADOW ENFORCEMENT
    // ============================================
    
    // Shadow mode: 'monitor', 'shadow', or 'block'
    // - monitor: Log only, don't block
    // - shadow: Slow down and confuse bots without alerting them
    // - block: Hard block (redirect immediately)
    'shadow_mode' => 'shadow',
    
    // Shadow tactics
    'shadow_tactics' => [
        'silent_rate_limit' => true,       // Apply rate limiting without alerting
        'response_delay_min' => 2000,      // Minimum delay in milliseconds
        'response_delay_max' => 5000,      // Maximum delay in milliseconds
        'fake_success_responses' => true,  // Return fake success data
        'perpetual_loading' => true,       // Show never-ending loading screens
    ],
    
    // Shadow rate limiting
    'shadow_rate_limit' => 10,            // Max requests per window
    'shadow_rate_window' => 60,           // Time window in seconds
    'shadow_block_duration' => 300,       // Block duration (5 minutes)
    
    // ============================================
    // STEALTH BOT DETECTION
    // ============================================
    
    // Advanced stealth detection features
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
    
    // TLS/JA3 fingerprinting
    'tls_fingerprinting' => [
        'enabled' => true,
        'enforce_ja3_match' => true,       // Require JA3 match for session
        'ja3_mismatch_penalty' => 100,     // Instant bot classification on mismatch
        'track_cipher_suites' => true,
        'track_header_order' => true,
    ],
    
    // ============================================
    // LOGGING & MONITORING
    // ============================================
    
    'log_file' => __DIR__ . '/logs/antibot.log',
    'security_log_file' => __DIR__ . '/logs/security.log',
    
    // Logging configuration for privacy
    'logging' => [
        'hash_fingerprints' => true,       // Hash IPs in general logs
        'hide_rejection_reasons' => true,  // Hide reasons in general logs (show in security log)
        'hide_raw_scores' => true,         // Hide raw scores (show ranges only)
        'separate_security_logs' => true,  // Keep detailed security log separate
    ],
    
    // Silent scoring (hide internal metrics from bots)
    'silent_scoring_enabled' => true,
    
    // ============================================
    // REPLAY ATTACK PREVENTION
    // ============================================
    
    'nonce_expiry' => 300,                // Nonce valid for 5 minutes (300 seconds)
    'nonce_cleanup_interval' => 3600,     // Clean old nonces hourly
    'hmac_algorithm' => 'sha256',         // HMAC hashing algorithm
    
    // ============================================
    // BEHAVIORAL ENTROPY REQUIREMENTS
    // ============================================
    
    // Minimum entropy thresholds (0-1 scale)
    'min_timing_entropy' => 0.2,          // Minimum variance in action timings
    'min_navigation_entropy' => 0.3,      // Minimum variance in navigation patterns
    'min_interaction_entropy' => 0.25,    // Minimum variance in interactions
    
    // Behavioral drift detection
    'drift_detection' => [
        'enabled' => true,
        'max_pattern_similarity' => 0.7,   // Max similarity before flagging (0-1)
        'min_sessions_for_drift' => 3,     // Need 3+ sessions to detect drift
        'drift_penalty' => 40,              // Penalty for no behavioral drift
    ],
    
    // ============================================
    // PERIODIC VERIFICATION
    // ============================================
    
    'periodic_verification' => [
        'enabled' => true,
        'interval_hours' => 4,             // Re-verify every 4 hours
        'ml_bot_detection' => true,        // Special handling for ML bots
        'long_session_threshold' => 7200,  // Flag sessions > 2 hours
    ],
];
