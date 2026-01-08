<?php
/**
 * Anti-Bot Configuration File (EXAMPLE)
 * 
 * SETUP INSTRUCTIONS:
 * 1. Copy this file to config.php: cp config.example.php config.php
 * 2. Edit config.php with your actual API keys and settings
 * 3. Never commit config.php to version control (it's in .gitignore)
 * 
 * For production use:
 * - Change all API keys to your actual keys
 * - Set strong passwords
 * - Review and adjust thresholds based on your needs
 */

return [
    // Log file location
    'log_file' => __DIR__ . '/logs/antibot.log',
    
    // Blacklist threshold (number of blacklist entries before blocking)
    'blacklist_threshold' => 2,
    
    // ProxyCheck risk threshold (0-100, higher = more strict)
    'proxycheck_risk_threshold' => 75,
    
    // Fingerprint salt - IMPORTANT: Change this to a random string
    // This is used for cryptographic fingerprinting
    // Generate a random string: openssl rand -base64 32
    'fingerprint_salt' => '',  // CHANGE THIS: Add a random 32+ character string
    
    // Neutrino API credentials (https://www.neutrinoapi.com/)
    // Sign up for free tier: 25 requests/day
    'user_id' => '',  // Your Neutrino User ID
    'api_key' => '',  // Your Neutrino API Key
    
    // ProxyCheck.io API key (https://proxycheck.io/)
    // Sign up for free tier: 100 queries/day
    'proxycheck_key' => '',  // Your ProxyCheck API key
    
    // Telegram Bot notifications (optional)
    'tg_bot_token' => '',  // Your Telegram Bot token from @BotFather
    'tg_chat_id' => '',    // Your Telegram Chat ID
];
