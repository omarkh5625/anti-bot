# Advanced Anti-Bot Detection System

An intelligent bot detection system that uses multiple behavioral analysis domains to differentiate between bots and human users while maintaining excellent user experience.

## Key Features

### 1. Multi-Domain Detection

#### Temporal Behavior Analysis
- **Stable Interaction Times**: Monitors interaction timing patterns across sessions
- **Equal Click Timing Detection**: Flags mathematically identical click intervals (bot indicator)
- **Hesitation Detection**: Tracks natural pauses and variations in user actions
- **Reading Time Analysis**: Measures reading duration based on content length

#### Interaction Noise Detection
- **Input Error Tracking**: Monitors typos, corrections, backspaces (human indicator)
- **Canceled Clicks**: Detects stray clicks and drag operations
- **Over-Efficiency Detection**: Flags suspiciously perfect navigation patterns
- **Visual Hint Response**: Tracks whether users respond to UI cues and hover states

#### UI Semantics Analysis
- **Cosmetic Element Interaction**: Monitors whether user interacts with decorative elements
- **Visual Order Sensitivity**: Detects if behavior changes with UI rearrangement
- **Robotic Pattern Detection**: Identifies repetitive, algorithmic interaction patterns

#### Session Continuity Monitoring
- **Navigation Pattern Analysis**: Tracks consistency and variation in page navigation
- **Session Resumption Logic**: Monitors natural session interruption and resumption
- **Repeated Pattern Detection**: Identifies suspicious identical session patterns

### 2. Smart UI Behavior

#### Seamless Access for Humans
- **No CAPTCHA for Confident Humans**: Users with strong human indicators bypass verification
- **Low Friction**: Minimal impact on legitimate user experience
- **Background Tracking**: Behavioral analysis happens transparently

#### Warning UI for Uncertain Cases
- **Targeted Verification**: CAPTCHA shown only when bot confidence is uncertain (20-60% range)
- **Cloudflare-Style Interface**: Familiar, professional verification UI
- **Enhanced Tracking**: Additional behavioral data collected during verification

#### Immediate Block for Likely Bots
- **High-Confidence Blocking**: Users with 60%+ bot score are redirected immediately
- **Detailed Logging**: All blocking reasons are logged for analysis
- **Multi-Layer Defense**: Combines behavioral analysis with traditional detection methods

## Architecture

### Backend Components (antibot.php)

```php
// Core Detection Functions
- calculate_bot_confidence($ip)          // Calculates overall bot confidence score
- analyze_temporal_patterns($ip)         // Analyzes timing patterns
- analyze_interaction_noise($ip)         // Evaluates interaction quality
- analyze_ui_semantics($ip)             // Monitors UI interaction patterns
- analyze_session_continuity($ip)       // Tracks session behavior

// Data Management
- track_temporal_behavior($ip, $action, $timestamp, $data)
- load_behavior_data()
- save_behavior_data($data)
```

### Frontend Components (antibot-tracking.js)

The tracking script monitors:
- Click patterns and timing
- Mouse movements and hover behavior
- Keyboard input and corrections
- Reading time on content
- Element interaction (decorative vs functional)
- Session navigation patterns
- Visibility changes and session resumption

## Integration

### Basic Setup

1. **Include the main protection file:**
```php
<?php
require_once 'config.php';  // Your configuration
require_once 'antibot.php'; // Anti-bot protection
?>
```

2. **Add behavioral tracking to protected pages:**
```html
<script src="/antibot-tracking.js"></script>
```

3. **Configure settings in config.php:**
```php
return [
    'log_file' => __DIR__ . '/logs/antibot.log',
    'blacklist_threshold' => 2,
    'proxycheck_risk_threshold' => 75,
    // ... other settings
];
```

### Configuration

Create a `config.php` file with your settings:

```php
<?php
return [
    'log_file' => __DIR__ . '/logs/antibot.log',
    'blacklist_threshold' => 2,
    'proxycheck_risk_threshold' => 75,
    'user_id' => 'YOUR_NEUTRINO_USER_ID',
    'api_key' => 'YOUR_NEUTRINO_API_KEY',
    'proxycheck_key' => 'YOUR_PROXYCHECK_KEY',
    'tg_bot_token' => 'YOUR_TELEGRAM_BOT_TOKEN',
    'tg_chat_id' => 'YOUR_TELEGRAM_CHAT_ID',
];
```

## Detection Scoring

### Bot Confidence Calculation

The system calculates a weighted bot confidence score (0-100%):

- **Temporal Behavior**: 30% weight
- **Interaction Noise**: 25% weight
- **UI Semantics**: 25% weight
- **Session Continuity**: 20% weight

### Confidence Ranges

- **< 20%**: Confident human - seamless access
- **20-60%**: Uncertain - show warning/CAPTCHA UI
- **≥ 60%**: Likely bot - immediate block

### Individual Domain Scoring

Each domain can contribute up to 100 points:

**Temporal Behavior:**
- Equal click timings: +30 points
- No hesitation: +25 points
- Constant reading times: +20 points

**Interaction Noise:**
- No errors/cancellations: +40 points
- Overly efficient: +35 points

**UI Semantics:**
- Ignores cosmetic elements: +45 points
- Unaffected by visual changes: +40 points

**Session Continuity:**
- Repeated identical patterns: +50 points
- Missing resume logic: +30 points

## Data Storage

### behavior_tracking.json
Stores per-IP behavioral data:
```json
{
  "192.168.1.100": {
    "first_seen": 1704672000,
    "sessions": {
      "sess_123": {
        "start_time": 1704672000,
        "actions": [
          {
            "action": "click",
            "timestamp": 1704672100,
            "data": {...}
          }
        ]
      }
    }
  }
}
```

## Security Features

- **IP Reputation Checking**: Integrates with Neutrino API
- **Proxy/VPN Detection**: Uses ProxyCheck.io
- **Geographic Filtering**: Country-based access control
- **User Agent Analysis**: Detects fake and headless browsers
- **Fingerprinting**: Tracks device fingerprints
- **Rate Limiting**: Monitors request patterns
- **Blacklist Management**: Persistent IP blocking

## Logging

All events are logged to the configured log file:

```
2026-01-08 10:30:45 | ALLOWED | IP: 192.168.1.100 | UA: Mozilla/5.0... | BotScore: 15 | Domains: temporal=10, noise=5, semantics=8, continuity=12
2026-01-08 10:31:12 | BLOCKED | IP: 10.0.0.50 | UA: HeadlessChrome... | Reason: Behavioral Analysis: Equal click timings, No hesitation
```

## UI/UX Principles

1. **Human-First Design**: Legitimate users should rarely see verification
2. **Progressive Verification**: Start with passive tracking, escalate only when needed
3. **Transparent Operation**: Most detection happens in background
4. **Fast Performance**: Minimal impact on page load and responsiveness
5. **Familiar Interface**: When verification is needed, use recognizable patterns

## Admin Monitoring Dashboard

### Access the Dashboard

Navigate to `admin-monitor.php` to access the comprehensive monitoring dashboard:

```
https://yourdomain.com/admin-monitor.php
```

**Default Password**: `admin123` (⚠️ **CHANGE THIS IN PRODUCTION!**)

Change the password in `admin-monitor.php`:
```php
define('ADMIN_PASSWORD', 'your_secure_password_here');
```

### Dashboard Features

#### Real-Time Statistics
- **Total Attempts**: All access attempts tracked
- **Humans**: Confident human users (< 20% bot score) - direct access
- **Uncertain**: Users shown CAPTCHA (20-57% bot score)
- **Bots Blocked**: High-confidence bots (≥ 57% bot score)
- **Automation Blocked**: Selenium, Puppeteer, Playwright, etc.
- **Detection Rate**: Percentage of blocked vs total attempts
- **Today/Last Hour**: Recent activity metrics

#### Access History (Last 50 Attempts)
View complete history with:
- Timestamp
- IP Address
- Verdict (Human, Bot, Uncertain, Automation)
- Bot Score (%)
- User Agent
- Detailed breakdown button

#### Detailed View Modal
Click "عرض التفاصيل" (View Details) on any entry to see:

**Bot Characteristics Tested:**
- Number of sessions
- Timing patterns (e.g., "Perfect 50ms intervals")
- Error rate percentage
- UI interaction behavior
- Session gap analysis

**Detection Domain Scores:**
- ⏱️ Temporal Behavior (30% weight)
- 🎯 Interaction Noise (25% weight)
- 🎨 UI Semantics (25% weight)
- 🔄 Session Continuity (20% weight)

**Detection Flags Raised:**
- List of specific bot indicators detected
- Automation tools identified (for automation blocks)

**Full User Agent String**

### Dashboard Screenshots

**Login Page:**
![Admin Login](https://github.com/user-attachments/assets/1b6049d5-d5bb-4495-9729-14720182cc4d)

**Main Dashboard:**
![Admin Dashboard](https://github.com/user-attachments/assets/1dba6cbe-ba71-42c7-9969-5c3c0dfc8e7a)

**Bot Details View:**
![Bot Details](https://github.com/user-attachments/assets/c9650d32-5156-4b75-9a98-822efcf04873)

**Automation Detection:**
![Automation Detection](https://github.com/user-attachments/assets/e04fbd2b-90a2-4f22-813d-ab47a31cda7f)

### Auto-Refresh

The dashboard automatically refreshes every 30 seconds to show the latest data. You can also manually refresh using the "🔄 تحديث" button.

### Security Notes

1. **Change Default Password**: The default password `admin123` should be changed immediately in production
2. **Access Control**: Consider adding IP whitelist or additional authentication
3. **HTTPS Required**: Always use HTTPS in production to protect admin credentials
4. **Session Security**: Dashboard uses PHP sessions with secure settings

## Best Practices

### For Protected Sites

1. **Include tracking script on all pages** for comprehensive behavioral data
2. **Monitor admin dashboard regularly** to tune detection thresholds
3. **Review bot characteristics** to understand attack patterns
4. **Whitelist known IPs** (office, testing, etc.)
5. **Test with real users** to avoid false positives
6. **Keep behavior data** for at least 7 days for pattern analysis
7. **Check automation blocks** to identify sophisticated bot tools

### For Developers

1. **Test in different browsers** and devices
2. **Monitor false positive rates** from admin dashboard
3. **Adjust domain weights** based on your traffic patterns
4. **Clear behavior data periodically** to avoid storage issues
5. **Use debug mode** (?debug=antibot) during development
6. **Review access logs** in the admin panel for insights

## Debug Mode

Enable debug mode by adding `?debug=antibot` to any URL:

```javascript
// In browser console
console.log(window.antibotTracker);
// Shows collected behavioral data
```

## Performance

- **Minimal overhead**: ~50KB tracking script
- **Efficient storage**: JSON-based with automatic cleanup
- **Async operations**: No blocking of main thread
- **Batched reporting**: Data sent every 10 actions or 30 seconds
- **Beacon API**: Reliable data transmission

## Compatibility

- **PHP**: 7.4+ (uses modern syntax like `??` and `?:`)
- **Browsers**: All modern browsers with ES6 support
- **Mobile**: Fully responsive, touch-event compatible
- **APIs**: Optional Neutrino and ProxyCheck integration

## Future Enhancements

- Machine learning-based pattern recognition
- Real-time threat intelligence integration
- Advanced fingerprinting techniques
- Anomaly detection algorithms
- WebGL and Canvas fingerprinting
- Audio context fingerprinting
- Battery and hardware API analysis

## License

This is a security tool. Use responsibly and in compliance with privacy regulations (GDPR, CCPA, etc.).

## Support

For issues or questions, review the logs first:
- `/logs/antibot.log` - Main activity log
- `/logs/blocked.txt` - Blocked requests
- `behavior_tracking.json` - Behavioral data
- `blocked_ips.json` - Blacklisted IPs

## Credits

Built with multiple detection domains to provide robust bot protection while maintaining excellent user experience.
