# 🛡️ Anti-Bot System

Advanced anti-bot protection system with behavioral analysis, dynamic fingerprinting, and session-network binding.

## ✨ Features

### 🔒 Advanced Bot Detection
- **Behavioral Analysis**: Tracks user interactions across 4 domains:
  - ⏱️ Temporal Behavior (30%): Timing patterns and hesitations
  - 🎯 Interaction Noise (25%): Errors, cancellations, natural variations
  - 🎨 UI Semantics (25%): Visual interaction patterns
  - 🔄 Session Continuity (20%): Navigation patterns and session gaps

### 🔐 Enhanced Security Features
- **Dynamic Salted Fingerprints**: Hourly-rotating cryptographic fingerprints prevent replay attacks
- **Session-Network Binding**: Ties sessions to network subnets to prevent session hijacking
- **TLS/HTTP Header Entropy**: JA3-style header analysis for advanced fingerprinting
- **Non-Linear Threat Scoring**: Amplifies high and low scores for decisive classification
- **Automation Detection**: Detects Selenium, WebDriver, Puppeteer, Playwright, and headless browsers

### 📊 Admin Dashboard
- Real-time statistics (Humans, Bots, Uncertain, Blocked)
- Detailed access logs with bot characteristics
- Domain score breakdowns
- Visual analytics and charts
- Password-protected access

## 🚀 Installation

### 1. Configure the System

```bash
# Copy the example config file
cp config.example.php config.php

# Edit config.php with your API keys
nano config.php
```

### 2. Set Up API Keys (Optional but Recommended)

#### Neutrino API (IP Reputation)
- Sign up at: https://www.neutrinoapi.com/
- Free tier: 25 requests/day
- Add your `user_id` and `api_key` to `config.php`

#### ProxyCheck.io (Proxy/VPN Detection)
- Sign up at: https://proxycheck.io/
- Free tier: 100 queries/day
- Add your API key to `config.php`

#### Telegram Notifications (Optional)
- Create a bot with @BotFather on Telegram
- Get your bot token and chat ID
- Add to `config.php`

### 3. File Permissions

```bash
# Create logs directory
mkdir -p logs
chmod 755 logs

# Ensure PHP can write to data files
chmod 644 fingerprints.json behavior_tracking.json blocked_ips.json
```

### 4. Include in Your Application

```php
<?php
// At the top of your protected pages
require_once 'antibot.php';

// Your page content here
?>
```

## 🎯 How It Works

### First Visit Flow
1. User lands on protected page
2. Shows "Checking your connection security..." for 5 seconds
3. Collects behavioral data (mouse movements, clicks, timing)
4. Analyzes behavior across 4 detection domains
5. Applies non-linear scoring for threat evaluation
6. Routes to appropriate path:
   - **High confidence human** (< 20% bot score): Direct access
   - **Uncertain** (20-57% bot score): CAPTCHA challenge
   - **Likely bot** (> 57% bot score): Blocked and redirected

### Session Management
- Dynamic fingerprints rotate every hour
- Session-network binding prevents hijacking
- Fingerprints include:
  - Hourly salt (prevents replay attacks)
  - Session ID binding
  - Network subnet (first 3 IP octets)
  - TLS/HTTP header entropy (JA3-style)

### Returning Visitors
- Verified humans get seamless access
- Session binding is checked on each request
- Network changes invalidate sessions
- Suspicious changes trigger re-verification

## 📊 Admin Monitor

Access the admin dashboard to view statistics and logs:

```
https://yourdomain.com/admin-monitor.php
```

**Default Password**: `admin123` (⚠️ **CHANGE THIS IMMEDIATELY!**)

### Dashboard Features
- Total attempts and detection rate
- Human/Bot/Uncertain statistics
- Real-time access logs (last 50)
- Detailed bot characteristics
- Domain score breakdowns
- Automation detection flags

## 🔧 Configuration

### Detection Thresholds

Edit constants in `antibot.php`:

```php
define('MIN_HUMAN_ACTION_TIME', 100);    // Minimum time between actions (ms)
define('SESSION_GAP_THRESHOLD', 5);      // Minimum session gap (seconds)
define('SESSION_GAP_SCORE', 30);         // Score penalty for suspicious gaps
```

### Admin Password

⚠️ **IMPORTANT**: Change the admin password in `admin-monitor.php`:

```php
define('ADMIN_PASSWORD', 'your_secure_password_here');
```

For production, use `password_hash()` and `password_verify()`.

### Whitelisted IPs

Add trusted IPs in `antibot.php`:

```php
function get_whitelisted_ips() {
    return [
        '127.0.0.1',
        'your.trusted.ip',
    ];
}
```

## 🛡️ Security Features Explained

### 1. Dynamic Salted Fingerprints
- Fingerprints change every hour
- Prevents attackers from reusing captured fingerprints
- Includes cryptographic salt in generation

### 2. Session-Network Binding
- Sessions are bound to the client's network subnet
- Changing networks invalidates the session
- Prevents session hijacking across different networks

### 3. TLS/HTTP Header Entropy
- Analyzes HTTP headers like JA3 fingerprinting
- Includes: User-Agent, Accept headers, Sec-CH-* headers
- Creates unique browser fingerprint

### 4. Non-Linear Scoring
- Low scores (< 20): Dampened by 0.5x → Strong human confidence
- Medium scores (20-50): Linear (0.9x) → Uncertain
- High scores (50-70): Amplified by 1.2x → Likely bot
- Very high scores (> 70): Amplified by 1.5x → Definitely bot

### 5. Behavioral Analysis Domains

#### Temporal Behavior (30% weight)
- Equal click timings → Bot indicator
- No hesitation (< 100ms) → Bot indicator
- Constant reading times → Bot indicator

#### Interaction Noise (25% weight)
- Zero errors/cancellations → Bot indicator
- Overly efficient (> 80%) → Bot indicator
- Natural human errors → Human indicator

#### UI Semantics (25% weight)
- Ignores decorative elements (> 90%) → Bot indicator
- Unaffected by visual changes → Bot indicator
- Follows visual cues → Human indicator

#### Session Continuity (20% weight)
- Identical navigation patterns → Bot indicator
- Session gaps < 5 seconds → Bot indicator
- Natural variation → Human indicator

## 📁 File Structure

```
anti-bot/
├── antibot.php              # Main anti-bot protection script
├── antibot-tracking.js      # Client-side behavioral tracking
├── admin-monitor.php        # Admin dashboard
├── config.example.php       # Configuration template
├── config.php               # Your configuration (not in git)
├── .gitignore              # Protects sensitive files
├── README.md               # This file
├── logs/                   # Log files directory
│   ├── antibot.log        # Main log
│   ├── automation.log     # Automation detection log
│   ├── access_log.json    # Structured access log
│   └── blocked.txt        # Blocked IPs
├── fingerprints.json       # Dynamic fingerprint data
├── behavior_tracking.json  # Behavioral analysis data
└── blocked_ips.json       # Blocked IP list
```

## 🧪 Testing

### Test as Human
1. Visit your protected page normally
2. Move your mouse naturally
3. Should get direct access (< 20% bot score)

### Test as Uncertain
1. Visit page with minimal interaction
2. Click immediately without natural movement
3. Should see CAPTCHA challenge

### Test Automation Detection
- Try with Selenium/WebDriver → Instant block
- Try with Puppeteer/Playwright → Instant block
- Headless browsers → Detected and blocked

## 📈 Best Practices

### Security
1. ✅ Change admin password immediately
2. ✅ Keep config.php out of version control
3. ✅ Use HTTPS in production
4. ✅ Regularly review blocked IPs
5. ✅ Monitor admin dashboard for patterns

### Performance
1. ✅ API calls are async and cached
2. ✅ Behavioral data is throttled (100ms)
3. ✅ Logs are limited (last 1000 entries)
4. ✅ Sessions auto-cleanup old data

### Maintenance
1. ✅ Review logs weekly
2. ✅ Adjust thresholds based on traffic
3. ✅ Update bot patterns periodically
4. ✅ Monitor false positives

## 🔄 Updates

### Recent Enhancements
- ✅ Fixed admin monitor statistics display
- ✅ Added dynamic salted fingerprints
- ✅ Implemented session-network binding
- ✅ Added TLS/HTTP header entropy analysis
- ✅ Implemented non-linear threat scoring
- ✅ Enhanced automation detection

## 📝 License

This is open-source software. Use at your own risk.

## 🆘 Support

For issues or questions:
1. Check the admin dashboard for patterns
2. Review logs in `logs/` directory
3. Adjust thresholds in configuration
4. Open an issue on GitHub

## ⚠️ Disclaimer

This system provides strong bot protection but is not 100% foolproof. Always:
- Monitor your logs
- Adjust thresholds for your use case
- Keep the system updated
- Use in combination with other security measures

---

Made with 🛡️ for better web security
