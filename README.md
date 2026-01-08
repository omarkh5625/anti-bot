# Advanced Anti-Bot Detection System

A comprehensive, multi-layer bot detection and mitigation system designed to protect web applications from automated threats including:

- ✅ Playwright Stealth bots
- ✅ Puppeteer Stealth bots  
- ✅ Selenium-based automation
- ✅ Headless browsers
- ✅ ML-powered bots
- ✅ Session hijacking attempts
- ✅ Replay attacks

## 🚀 Features

### Advanced Detection Layers

1. **Stealth Bot Detection**
   - Detects Playwright Stealth evasion techniques
   - Identifies Puppeteer Stealth plugin artifacts
   - Catches Selenium WebDriver automation
   - Recognizes headless browser patterns

2. **TLS/JA3 Fingerprinting**
   - Creates unique client fingerprints from TLS handshake
   - Tracks SSL/TLS protocol, cipher suites, and header patterns
   - Prevents session hijacking and replay attacks
   - Enforces fingerprint consistency across sessions

3. **Multi-Factor Session Binding**
   - IP subnet verification (NAT-friendly)
   - TLS/JA3 fingerprint matching
   - User-Agent hash validation
   - Configurable enforcement levels

4. **Behavioral Analysis (7 Domains)**
   - Temporal behavior patterns
   - Interaction noise (errors, corrections)
   - UI semantics understanding
   - Session continuity
   - Mouse movement entropy
   - Idealized behavior detection
   - Behavioral drift analysis

5. **Canvas & Audio Fingerprinting**
   - Unique canvas rendering analysis
   - Audio context processing detection
   - Identifies headless environments

6. **Dynamic Scoring System**
   - Non-linear score amplification
   - Randomized weights (anti-reverse-engineering)
   - Variable detection thresholds
   - Adaptive classification

7. **Shadow Enforcement Layer**
   - Silent bot degradation (no alerts)
   - Fake success responses
   - Artificial delays and rate limiting
   - Resource exhaustion tactics

## 📋 Requirements

- PHP 7.4 or higher
- Modern web browser (for legitimate users)
- SSL/TLS enabled (recommended)
- Write permissions for logs directory

## 🔧 Installation

1. **Upload files to your web server:**
   ```
   antibot.php          - Main detection engine
   antibot-tracking.js  - Client-side behavioral tracking
   config.php          - Configuration file
   admin-monitor.php   - Admin dashboard
   ```

2. **Create logs directory:**
   ```bash
   mkdir logs
   chmod 755 logs
   ```

3. **Configure the system:**

   Edit `config.php`:
   ```php
   return [
       // Generate unique salt for your installation
       'fingerprint_salt' => 'CHANGE_THIS_TO_RANDOM_STRING',
       
       // Set shadow enforcement mode
       'shadow_mode' => 'shadow',  // 'monitor', 'shadow', or 'block'
       
       // API keys (optional but recommended)
       'user_id' => 'your_neutrino_id',
       'api_key' => 'your_neutrino_key',
       'proxycheck_key' => 'your_proxycheck_key',
   ];
   ```

   Generate a secure salt:
   ```bash
   openssl rand -hex 32
   ```

4. **Change admin password:**

   Edit `admin-monitor.php`:
   ```php
   define('ADMIN_PASSWORD', 'YOUR_STRONG_PASSWORD_HERE');
   ```

5. **Include antibot.php in your pages:**
   ```php
   <?php
   // At the very top of your protected pages
   require_once 'antibot.php';
   ?>
   ```

6. **Add tracking script to HTML:**
   ```html
   <script src="antibot-tracking.js"></script>
   ```

## 🎯 Quick Start

### Basic Protection

Minimal setup for immediate protection:

```php
<?php
// page.php
require_once 'antibot.php';
?>
<!DOCTYPE html>
<html>
<head>
    <title>Protected Page</title>
</head>
<body>
    <h1>Your Content</h1>
    
    <!-- Add tracking at the end -->
    <script src="antibot-tracking.js"></script>
</body>
</html>
```

That's it! The system will now:
- ✅ Detect automation tools automatically
- ✅ Track behavioral patterns
- ✅ Enforce session binding
- ✅ Block or shadow-ban bots

### Advanced Configuration

For fine-tuned control, customize `config.php`:

```php
return [
    // Detection sensitivity
    'threshold_human_min' => 15,      // Lower = more strict for humans
    'threshold_human_max' => 25,
    'threshold_bot_min' => 50,        // Lower = catch more bots
    'threshold_bot_max' => 65,
    
    // Session binding enforcement
    'enforce_subnet_binding' => true,  // Require same IP subnet
    'enforce_tls_binding' => true,     // Require same TLS fingerprint
    'enforce_ua_binding' => true,      // Require same user-agent
    
    // Mouse movement analysis
    'mouse_analysis' => [
        'min_entropy' => 0.3,           // Minimum movement randomness
        'curve_smoothness_max' => 0.9,  // Maximum curve smoothness
        'min_jitter_variance' => 0.1,   // Minimum hand tremor
        'jitter_required' => true,
    ],
    
    // Behavioral drift detection
    'drift_detection' => [
        'enabled' => true,
        'max_pattern_similarity' => 0.7,  // Flag static behavior
        'min_sessions_for_drift' => 3,
        'drift_penalty' => 40,
    ],
    
    // Shadow enforcement
    'shadow_mode' => 'shadow',  // Options: monitor, shadow, block
    'shadow_tactics' => [
        'silent_rate_limit' => true,
        'response_delay_min' => 2000,   // ms
        'response_delay_max' => 5000,
        'fake_success_responses' => true,
        'perpetual_loading' => true,
    ],
];
```

## 📊 Admin Dashboard

Access the monitoring dashboard:

```
http://your-site.com/admin-monitor.php
```

**Default credentials:**
- Username: (none required)
- Password: `admin123` (⚠️ CHANGE THIS IMMEDIATELY!)

The dashboard provides:
- 📈 Real-time statistics (humans vs bots)
- 📋 Recent access attempts
- 🎯 Bot detection scores
- 🔍 Detailed behavioral analysis
- 📊 Detection domain breakdowns
- 🚨 Automation flags

## 🛡️ How It Works

### Detection Flow

```
┌─────────────────┐
│  User Request   │
└────────┬────────┘
         │
         ▼
┌─────────────────────┐
│ Basic Checks        │
│ - User Agent        │
│ - IP Reputation     │
│ - Known Bot Lists   │
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│ Automation Detect   │
│ - WebDriver flags   │
│ - Stealth plugins   │
│ - Headless patterns │
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│ Behavioral Analysis │
│ (5-second window)   │
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│ Session Binding     │
│ - IP Subnet         │
│ - JA3 Fingerprint   │
│ - User-Agent Hash   │
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│ Bot Scoring         │
│ (7 detection domains)│
└────────┬────────────┘
         │
         ▼
    ┌───┴────┐
    │        │
    ▼        ▼
┌─────┐  ┌──────┐  ┌──────────┐
│Human│  │Unsure│  │   Bot    │
│     │  │      │  │          │
│Pass │  │CAPTCH│  │Shadow Ban│
│     │  │A     │  │or Block  │
└─────┘  └──────┘  └──────────┘
```

### Detection Domains (Weighted)

| Domain | Weight | Detection Target |
|--------|--------|------------------|
| Temporal Behavior | 18% | Action timing patterns, delays |
| Mouse Movements | 18% | Entropy, jitter, smoothness |
| Interaction Noise | 13% | Errors, corrections, hesitations |
| UI Semantics | 13% | Understanding of visual elements |
| Session Continuity | 13% | Navigation patterns |
| Idealized Behavior | 13% | Perfect, inhuman patterns |
| Behavioral Drift | 12% | Static vs dynamic behavior |

### Shadow Enforcement

Instead of immediately blocking bots, the system can:

1. **Apply artificial delays** (2-5 seconds)
2. **Return fake success responses** with empty data
3. **Show perpetual loading screens**
4. **Rate limit silently** without errors

This:
- ✅ Wastes bot resources
- ✅ Prevents reverse engineering
- ✅ Doesn't alert bot operators
- ✅ Gathers intelligence on bot behavior

## 🔐 Security Best Practices

### 1. Secure Configuration

```bash
# Move config.php outside web root
mv config.php /var/www/config/antibot-config.php

# Update antibot.php
$config = require '/var/www/config/antibot-config.php';

# Set strict permissions
chmod 600 /var/www/config/antibot-config.php
```

### 2. Rotate Fingerprint Salt

```bash
# Generate new salt monthly
openssl rand -hex 32

# Update in config.php
'fingerprint_salt' => 'new_salt_here',
```

### 3. Monitor Logs

```bash
# Watch real-time detections
tail -f logs/automation.log
tail -f logs/security.log

# Review admin dashboard daily
```

### 4. Use HTTPS

JA3 fingerprinting works best with SSL/TLS:
```nginx
# nginx configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
```

### 5. API Keys (Optional)

For enhanced IP reputation checking:

- **Neutrino API**: https://www.neutrinoapi.com/
- **ProxyCheck.io**: https://proxycheck.io/

Add to `config.php`:
```php
'user_id' => 'your_neutrino_id',
'api_key' => 'your_neutrino_key',
'proxycheck_key' => 'your_proxycheck_key',
```

## 🐛 Troubleshooting

### High False Positive Rate

Users are being incorrectly flagged as bots:

```php
// In config.php
'threshold_bot_min' => 60,     // Increase (was 50)
'threshold_human_max' => 30,   // Increase (was 25)
'jitter_required' => false,    // Disable if touchscreen users affected
```

### Bots Getting Through

Bots are bypassing detection:

```php
// In config.php
'threshold_bot_min' => 40,      // Decrease (was 50)
'threshold_human_min' => 10,    // Decrease (was 15)
'enforce_tls_binding' => true,  // Ensure enabled
'drift_detection' => [
    'max_pattern_similarity' => 0.6,  // Lower (was 0.7)
],
```

### Performance Issues

System is slow:

```php
// In config.php
'stealth_detection' => [
    'check_audio_fingerprint' => false,  // Disable heavy checks
],

// In antibot-tracking.js
const SEND_INTERVAL_MS = 60000;      // Increase (was 30000)
const MAX_MOUSE_MOVEMENTS = 50;      // Reduce (was 100)
```

### Session Issues

Users being re-verified frequently:

```php
// In config.php
'session_max_age' => 86400 * 7,      // 7 days (was 24 hours)
'session_trust_decay_rate' => 2,     // Slower decay (was 5)
'enforce_subnet_binding' => false,   // If users change networks
```

## 📈 Monitoring & Analytics

### Key Metrics to Track

1. **Detection Rate**
   ```
   (Bots Blocked + Shadow Banned) / Total Attempts
   ```

2. **False Positive Rate**
   ```
   Humans Challenged / Total Human Attempts
   ```

3. **Average Bot Score**
   - Humans: < 25 (ideal)
   - Bots: > 50 (ideal)

4. **Session Binding Violations**
   - Monitor `logs/security.log`
   - Look for repeated violations from same IP

### Log Analysis

```bash
# Count automation detections
grep "AUTOMATION DETECTED" logs/automation.log | wc -l

# Count session binding violations
grep "SESSION_BINDING_VIOLATION" logs/security.log | wc -l

# Count JA3 mismatches
grep "JA3_MISMATCH" logs/security.log | wc -l

# View top bot IPs
grep "BLOCKED" logs/antibot.log | awk '{print $6}' | sort | uniq -c | sort -rn | head -10
```

## 🚀 Advanced Usage

### Custom Integration

```php
<?php
require_once 'antibot.php';

// Check if current request is likely a bot
$client_ip = get_client_ip();
$bot_analysis = calculate_bot_confidence($client_ip);

if ($bot_analysis['is_likely_bot']) {
    // Custom action for bots
    error_log("Bot detected: " . json_encode($bot_analysis));
    
    // Shadow ban
    apply_shadow_enforcement($client_ip, $bot_analysis['confidence'], $config);
    exit;
}

// Continue with normal flow
?>
```

### Custom Detection Rules

Add custom checks in `antibot.php`:

```php
function custom_bot_check($ip, $user_agent) {
    // Example: Block specific user agent patterns
    if (preg_match('/YourBotPattern/i', $user_agent)) {
        return ['score' => 100, 'reasons' => ['Custom pattern matched']];
    }
    
    // Example: Check custom headers
    if (isset($_SERVER['HTTP_X_CUSTOM']) && $_SERVER['HTTP_X_CUSTOM'] === 'bot') {
        return ['score' => 100, 'reasons' => ['Custom header detected']];
    }
    
    return ['score' => 0, 'reasons' => []];
}

// Add to calculate_bot_confidence()
$custom = custom_bot_check($ip, $_SERVER['HTTP_USER_AGENT'] ?? '');
```

## 📚 Documentation

- [Security Enhancements](SECURITY_ENHANCEMENTS.md) - Detailed technical documentation
- Admin Dashboard - Built-in monitoring interface
- Logs Directory - Real-time detection logs

## 🤝 Contributing

Contributions are welcome! Areas for improvement:

- [ ] Machine learning model integration
- [ ] Real-time IP reputation database
- [ ] Browser extension detection
- [ ] Advanced CAPTCHA integration
- [ ] Multi-language support
- [ ] Rate limiting per endpoint

## ⚠️ Important Notes

1. **Legal Compliance**: Ensure your anti-bot measures comply with local laws and regulations
2. **Privacy**: System logs IP addresses - comply with GDPR/privacy laws
3. **False Positives**: Test thoroughly with legitimate users before production
4. **Accessibility**: Ensure CAPTCHA is accessible to users with disabilities
5. **Performance**: Monitor system performance on high-traffic sites

## 📝 License

This project is provided as-is for security purposes. Use responsibly.

## 🔒 Security Disclosure

Found a security vulnerability? Please report responsibly:
1. Do not publicly disclose
2. Contact via secure channel
3. Allow time for fix before disclosure

## 🌟 Support

Need help?
1. Check [SECURITY_ENHANCEMENTS.md](SECURITY_ENHANCEMENTS.md) for detailed documentation
2. Review logs: `logs/antibot.log` and `logs/security.log`
3. Test with browser developer tools open
4. Verify configuration in `config.php`

---

**Built with security in mind. Protecting web applications from automated threats.**
