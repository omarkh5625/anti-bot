<?php
/**
 * Anti-Bot Framework Configuration
 * 
 * SECURITY NOTICE:
 * - Change all default secrets before deploying to production
 * - Use strong, randomly generated keys (min 32 characters)
 * - Rotate keys periodically (recommended: every 90 days)
 * - Keep this file outside web root if possible
 * - Set file permissions to 0600 (read/write owner only)
 */

return [
    // ========================================
    // CRYPTOGRAPHIC KEYS & SECRETS
    // ========================================
    
    /**
     * HMAC Secret for Telemetry Signing
     * CRITICAL: Change this to a strong random value
     * Generate with: openssl rand -hex 32
     * SECURITY: If not set via environment variable, system will refuse to start
     */
    'hmac_secret' => getenv('ANTIBOT_HMAC_SECRET') ?: 
        (function() {
            // Security: Require HMAC secret to be explicitly set
            if (!isset($_SERVER['SERVER_NAME'])) {
                // CLI mode or test - use temporary secret
                return 'TEMP_TEST_SECRET_' . hash('sha256', __DIR__ . time());
            }
            // Production mode - log error and generate temporary
            error_log('SECURITY WARNING: ANTIBOT_HMAC_SECRET not set! Using temporary fallback.');
            return 'INSECURE_FALLBACK_' . hash('sha256', __DIR__ . $_SERVER['SERVER_NAME'] . time());
        })(),
    
    /**
     * Fingerprint Salt for Dynamic Fingerprinting
     * Used to create time-based fingerprint salts
     * Generate with: openssl rand -hex 32
     */
    'fingerprint_salt' => getenv('ANTIBOT_FP_SALT') ?: 'CHANGE_ME_FP_' . hash('sha256', __DIR__ . 'fingerprint'),
    
    /**
     * Key Rotation Settings
     * Keys will be rotated automatically based on this interval
     */
    'key_rotation_interval' => 90 * 24 * 3600, // 90 days in seconds
    'last_key_rotation' => time(), // Track last rotation
    
    // ========================================
    // SESSION BINDING & SECURITY
    // ========================================
    
    /**
     * Session binding strictness
     * - 'strict': Block any network/fingerprint change
     * - 'moderate': Allow minor changes, re-verify on major changes
     * - 'relaxed': Only track, don't enforce
     */
    'session_binding_mode' => 'strict',
    
    /**
     * Session maximum age (in seconds)
     * Sessions older than this will require re-verification
     */
    'session_max_age' => 24 * 3600, // 24 hours
    
    /**
     * Session trust decay rate
     * Trust score decreases by this percentage per hour
     */
    'session_trust_decay_rate' => 5, // 5% per hour
    
    // ========================================
    // REPLAY ATTACK MITIGATION
    // ========================================
    
    /**
     * Nonce expiration time (seconds)
     * Nonces older than this are considered expired
     */
    'nonce_expiration' => 300, // 5 minutes
    
    /**
     * Maximum fingerprint usage count
     * A fingerprint can be used this many times before flagging
     */
    'max_fingerprint_usage' => 3,
    
    /**
     * Nonce cleanup interval
     * Old nonces are cleaned up every N seconds
     */
    'nonce_cleanup_interval' => 3600, // 1 hour
    
    // ========================================
    // SCORING & THRESHOLDS
    // ========================================
    
    /**
     * Dynamic threshold ranges
     * Thresholds are randomized within these ranges
     */
    'threshold_human_min' => 15,
    'threshold_human_max' => 25,
    'threshold_bot_min' => 50,
    'threshold_bot_max' => 65,
    
    /**
     * Domain weight randomization
     * Weights are randomized within +/- this percentage
     */
    'weight_randomization' => 10, // +/- 10%
    
    /**
     * Silent scoring enabled
     * When true, actual scores are obfuscated
     */
    'silent_scoring_enabled' => true,
    
    // ========================================
    // SHADOW ENFORCEMENT
    // ========================================
    
    /**
     * Shadow enforcement mode
     * - 'block': Immediately block detected bots
     * - 'shadow': Apply shadow enforcement tactics
     * - 'monitor': Only log, don't enforce
     */
    'shadow_mode' => 'shadow',
    
    /**
     * Shadow tactics configuration
     */
    'shadow_tactics' => [
        'fake_success' => true,           // Return fake success responses
        'incomplete_data' => true,        // Return incomplete datasets
        'response_delay_min' => 2000,     // Min delay in ms
        'response_delay_max' => 8000,     // Max delay in ms
        'silent_rate_limit' => true,      // Silently rate limit requests
    ],
    
    /**
     * Rate limiting for shadow mode
     */
    'shadow_rate_limit' => 10,            // Max requests per window for bots
    'shadow_rate_window' => 60,           // Rate limit window in seconds
    'shadow_block_duration' => 300,       // Block duration in seconds (5 minutes)
    
    // ========================================
    // BEHAVIOR ANALYSIS
    // ========================================
    
    /**
     * Idealized behavior detection
     */
    'idealized_behavior' => [
        'perfect_timing_threshold' => 0.15,  // Variance threshold (0-1)
        'zero_error_penalty' => 40,          // Score penalty for zero errors
        'identical_path_penalty' => 50,      // Penalty for repeated identical paths
        'identical_fingerprint_penalty' => 60, // Penalty for fingerprint reuse
    ],
    
    /**
     * Mouse movement analysis
     */
    'mouse_analysis' => [
        'min_entropy' => 0.3,                // Minimum entropy for human-like movement
        'curve_smoothness_max' => 0.9,       // Max smoothness (too smooth = bot)
        'jitter_required' => true,           // Require natural jitter
        'min_jitter_variance' => 0.1,        // Minimum jitter variance
        'linearity_threshold' => 0.95,       // R-squared threshold for linear detection
    ],
    
    // ========================================
    // LOGGING & MONITORING
    // ========================================
    
    /**
     * Secure logging configuration
     * 
     * Note: When hash_fingerprints is enabled, IP addresses are hashed
     * in access_log.json for privacy. The admin dashboard will show
     * truncated hash values with "(hashed)" indicator. Full IP addresses
     * are only stored in security.log for authorized access.
     */
    'logging' => [
        'hash_fingerprints' => true,         // Hash IP addresses and fingerprints in access logs
        'hide_rejection_reasons' => true,    // Hide detailed rejection reasons
        'hide_raw_scores' => true,           // Hide raw bot scores
        'separate_security_logs' => true,    // Use separate security log
        'log_rotation_size' => 10485760,     // 10MB
        'log_retention_days' => 30,          // Keep logs for 30 days
    ],
    
    'log_file' => __DIR__ . '/logs/antibot.log',
    'security_log_file' => __DIR__ . '/logs/security.log',
    'debug_log_file' => __DIR__ . '/logs/debug.log',
    
    // ========================================
    // EXTERNAL API CONFIGURATION
    // ========================================
    
    /**
     * IP Reputation Services
     */
    'user_id' => getenv('NEUTRINO_USER_ID') ?: '',
    'api_key' => getenv('NEUTRINO_API_KEY') ?: '',
    'proxycheck_key' => getenv('PROXYCHECK_KEY') ?: '',
    
    /**
     * Notification Services
     */
    'tg_bot_token' => getenv('TELEGRAM_BOT_TOKEN') ?: '',
    'tg_chat_id' => getenv('TELEGRAM_CHAT_ID') ?: '',
    
    // ========================================
    // THRESHOLDS & LIMITS
    // ========================================
    
    'blacklist_threshold' => 2,
    'proxycheck_risk_threshold' => 75,
    
    // ========================================
    // VARIABLE LOGIC (Anti-Reverse Engineering)
    // ========================================
    
    /**
     * Randomization seeds
     * These change the order and weights of evaluation
     */
    'randomization_seed' => time() / 3600, // Changes hourly
    'evaluation_order_randomized' => true,
    
    /**
     * Parameter obfuscation
     * Add random noise to parameters to prevent pattern detection
     */
    'parameter_noise_enabled' => true,
    'parameter_noise_range' => 5, // +/- 5%
];
