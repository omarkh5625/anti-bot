# Anti-Bot Framework - Advanced Security Enhancement

## 🔒 Overview

This is an advanced anti-bot framework designed to detect and mitigate sophisticated bot attacks while maintaining a seamless experience for legitimate users. The framework implements multiple layers of security including cryptographic signing, behavioral analysis, session binding, and shadow enforcement.

## ✨ Key Features

### 1. **Cryptographic Signing & Replay Protection**
- HMAC-SHA256 signature verification for all telemetry data
- Nonce-based replay attack prevention
- 5-minute nonce expiration window
- Constant-time signature comparison to prevent timing attacks

### 2. **Session Binding & TLS Fingerprinting**
- JA3-like fingerprinting from HTTP headers
- Dynamic fingerprints with hourly salt rotation
- IP subnet binding
- Automatic session invalidation on network changes
- Header entropy analysis for bot detection

### 3. **Advanced Behavioral Analysis**
- **6 Independent Detection Domains:**
  1. **Temporal Behavior**: Click timing patterns, hesitation detection
  2. **Interaction Noise**: Error rates, canceled actions, natural mistakes
  3. **UI Semantics**: Decorative vs functional element interaction
  4. **Session Continuity**: Navigation patterns, session gaps
  5. **Mouse Movement Analysis**: Entropy, jitter, smoothness, linearity
  6. **Idealized Behavior Detection**: Perfect timing, zero errors, identical patterns

### 4. **Non-Linear Scoring System**
- Dynamic score amplification (high scores amplified, low scores dampened)
- Randomized domain weights (+/- 10% variance)
- Dynamic thresholds (varies per evaluation)
- Silent scoring mode (hides internal metrics)

### 5. **Shadow Enforcement**
- Configurable modes: `monitor`, `shadow`, `block`
- Fake success responses for bots
- Response delays (2-8 seconds)
- Silent rate limiting (10 requests/minute)
- Incomplete data returns
- Perpetual loading pages

### 6. **Session Aging & Trust Decay**
- 5% trust decay per hour
- 24-hour maximum session age
- Automatic re-verification when trust < 30%
- Behavioral deviation detection

### 7. **Secure Logging**
- Hashed IP addresses in access logs
- Hidden rejection reasons
- Hidden raw scores
- Separate security and access logs
- Configurable log retention

### 8. **Anti-Reverse Engineering**
- Randomized evaluation order
- Variable weights and thresholds
- Obfuscated internal metrics
- Parameter noise injection

## 🚀 Quick Start

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/omarkh5625/anti-bot.git
   cd anti-bot
   ```

2. **Configure secrets in `config.php`:**
   ```php
   'hmac_secret' => 'YOUR_STRONG_SECRET_HERE',
   'fingerprint_salt' => 'YOUR_UNIQUE_SALT_HERE',
   ```

3. **Set environment variables (recommended for production):**
   ```bash
   export ANTIBOT_HMAC_SECRET="your-secret-key"
   export ANTIBOT_FP_SALT="your-fingerprint-salt"
   export NEUTRINO_USER_ID="your-neutrino-id"
   export NEUTRINO_API_KEY="your-neutrino-key"
   ```

4. **Include in your protected page:**
   ```php
   <?php
   // At the top of your protected page
   require_once 'antibot.php';
   
   // Your page content here
   ?>
   ```

### Configuration

Edit `config.php` to customize behavior:

```php
return [
    // Cryptographic Keys
    'hmac_secret' => getenv('ANTIBOT_HMAC_SECRET') ?: 'CHANGE_ME',
    'fingerprint_salt' => getenv('ANTIBOT_FP_SALT') ?: 'CHANGE_ME',
    
    // Session Settings
    'session_binding_mode' => 'strict', // strict, moderate, relaxed
    'session_max_age' => 24 * 3600, // 24 hours
    'session_trust_decay_rate' => 5, // 5% per hour
    
    // Shadow Enforcement
    'shadow_mode' => 'shadow', // monitor, shadow, block
    'shadow_tactics' => [
        'fake_success' => true,
        'response_delay_min' => 2000,
        'response_delay_max' => 8000,
    ],
    
    // Scoring & Thresholds
    'threshold_human_min' => 15,
    'threshold_human_max' => 25,
    'threshold_bot_min' => 50,
    'threshold_bot_max' => 65,
    'weight_randomization' => 10, // +/- 10%
    
    // Logging
    'logging' => [
        'hash_fingerprints' => true,
        'hide_rejection_reasons' => true,
        'hide_raw_scores' => true,
        'separate_security_logs' => true,
    ],
];
```

## 📊 Monitoring Dashboard

Access the admin monitoring dashboard at `admin-monitor.php`:

1. **Default password:** `admin123` (⚠️ CHANGE IMMEDIATELY!)
2. **Features:**
   - Real-time statistics
   - Access history with bot characteristics
   - Detection domain scores
   - Automation flags
   - Behavioral patterns

## 🔐 Security Best Practices

### 1. **Key Management**
- Use strong, randomly generated keys (32+ characters)
- Rotate keys every 90 days
- Store keys in environment variables, not in code
- Use different keys for development and production

### 2. **File Permissions**
```bash
chmod 600 config.php           # Only owner can read/write
chmod 755 antibot.php           # Owner can execute, others read
chmod 700 logs/                 # Only owner can access logs
```

### 3. **Log Management**
- Rotate logs regularly
- Keep security logs separate from access logs
- Restrict access to security logs
- Never log sensitive user data (passwords, tokens)

### 4. **Monitoring**
- Check `logs/security.log` for attack patterns
- Monitor detection rates in admin dashboard
- Set up alerts for high bot detection rates
- Review false positives regularly

## 📝 Detection Logic

### Bot Confidence Scoring

The framework analyzes 6 domains and combines them with dynamic weights:

```
Base Weights (randomized ±10%):
- Temporal Behavior: 20%
- Interaction Noise: 15%
- UI Semantics: 15%
- Session Continuity: 15%
- Mouse Movement: 20%
- Idealized Behavior: 15%

Non-Linear Transformation:
- Score < 20: dampened (×0.5)
- Score 20-50: linear (×0.9)
- Score 50-70: amplified (×1.2)
- Score > 70: highly amplified (×1.5)

Dynamic Thresholds (randomized per request):
- Human: 15-25 (random)
- Bot: 50-65 (random)
```

### Decision Flow

```
1. First Visit
   ↓
2. Show analysis page (collect 5s of behavior)
   ↓
3. Calculate bot confidence
   ↓
4. Decision:
   - < threshold_human → Allow (seamless)
   - threshold_human to threshold_bot → Show CAPTCHA
   - ≥ threshold_bot → Shadow enforcement or block
```

## 🧪 Testing

Run the test suite:

```bash
php test-antibot.php
```

Tests verify:
- Configuration loading
- HMAC signature generation
- Nonce validation (expiry, future, replay)
- Dynamic fingerprinting
- IP subnet extraction
- Shadow enforcement
- Session trust calculation
- Non-linear scoring
- Dynamic thresholds
- Secure logging configuration

## 🔧 Troubleshooting

### Issue: "Unsigned telemetry" errors in logs
**Solution:** Ensure JavaScript is enabled and SubtleCrypto API is available. Fallback signing is used for older browsers.

### Issue: Legitimate users getting blocked
**Solution:** 
1. Check if thresholds are too aggressive
2. Increase `threshold_bot_min` in config
3. Switch to `shadow_mode => 'monitor'` temporarily to observe
4. Review false positives in admin dashboard

### Issue: Bots bypassing detection
**Solution:**
1. Enable stricter session binding: `session_binding_mode => 'strict'`
2. Lower bot threshold: `threshold_bot_max => 55`
3. Enable all shadow tactics
4. Check if keys need rotation

### Issue: High server load
**Solution:**
1. Reduce `nonce_cleanup_interval`
2. Limit stored behavioral data size
3. Use caching for IP reputation checks
4. Consider moving analysis to background job

## 📈 Performance

- **Overhead per request:** ~2-5ms (excluding external API calls)
- **Memory usage:** ~1-2MB per session
- **Storage:** ~1KB per user session
- **Recommended:** PHP 7.4+ for optimal performance

## 🛡️ Attack Mitigation

### Successfully Mitigates:
✅ Selenium/WebDriver automation  
✅ Headless browsers (Puppeteer, Playwright)  
✅ Replay attacks  
✅ Session hijacking  
✅ IP rotation  
✅ VPN/Proxy abuse  
✅ Scripted interactions  
✅ Perfect timing bots  
✅ Zero-error bots  
✅ Navigation replay attacks  

### Advanced Detection:
- CDP (Chrome DevTools Protocol) indicators
- WebGL software rendering
- Missing browser features
- Automation properties in window object
- Mouse movement analysis (entropy, jitter, linearity)
- Behavioral consistency over time

## 📄 License

[Add your license here]

## 🤝 Contributing

[Add contribution guidelines here]

## 📞 Support

For issues and questions:
- Check `logs/security.log` for detailed information
- Review admin dashboard for patterns
- Consult this README for troubleshooting

## 🔄 Changelog

### Version 2.0.0 (2026-01-08)
- ✨ Added HMAC-SHA256 cryptographic signing
- ✨ Implemented nonce-based replay protection
- ✨ Added session binding with JA3-like fingerprinting
- ✨ Implemented advanced mouse movement analysis
- ✨ Added 6-domain behavioral analysis
- ✨ Implemented non-linear scoring system
- ✨ Added dynamic thresholds with randomization
- ✨ Implemented shadow enforcement layer
- ✨ Added session aging and trust decay
- ✨ Implemented idealized behavior detection
- ✨ Added secure logging with hash obfuscation
- ✨ Added anti-reverse engineering measures

---

**⚠️ Security Notice:** This framework provides strong bot protection but is not foolproof. Always combine with other security measures (rate limiting, CAPTCHA, WAF, etc.) for comprehensive protection.
