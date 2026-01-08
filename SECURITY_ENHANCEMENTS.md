# Anti-Bot Detection System - Security Enhancements

This document describes the comprehensive security enhancements made to the anti-bot detection system to address advanced stealth bots and sophisticated attacks.

## Table of Contents
1. [Overview](#overview)
2. [Advanced Stealth Bot Detection](#advanced-stealth-bot-detection)
3. [TLS/JA3 Fingerprinting](#tlsja3-fingerprinting)
4. [Enhanced Session Binding](#enhanced-session-binding)
5. [Behavioral Drift Detection](#behavioral-drift-detection)
6. [Dynamic Scoring System](#dynamic-scoring-system)
7. [Shadow Enforcement Layer](#shadow-enforcement-layer)
8. [Configuration Guide](#configuration-guide)

## Overview

The anti-bot system now includes multiple layers of detection to identify and block:
- **Playwright Stealth** - Advanced automation tool with evasion techniques
- **Puppeteer Stealth** - Headless Chrome automation with stealth plugins
- **Selenium with evasion** - Traditional automation with anti-detection
- **ML-based bots** - Sophisticated bots using machine learning
- **Session hijacking** - Attempts to steal or replay sessions

## Advanced Stealth Bot Detection

### Playwright Stealth Detection

The system detects Playwright Stealth through multiple vectors:

1. **Webdriver Property Analysis**
   - Detects `navigator.webdriver === false` (stealth plugins set this)
   - Real browsers don't have this property at all

2. **Descriptor Modification Detection**
   - Checks `Object.getOwnPropertyDescriptor()` for modified properties
   - Detects proxy-based evasion techniques

3. **Chrome Runtime Inconsistencies**
   - Identifies missing `window.chrome.runtime` in Chrome user-agents
   - Playwright often has incomplete Chrome emulation

4. **Plugin/MIME Type Analysis**
   - Detects empty plugin lists in Chrome browsers
   - Real Chrome browsers always have plugins

### Puppeteer Stealth Detection

1. **Empty Plugin Detection**
   - Identifies browsers with zero plugins and mime types
   - Puppeteer-stealth often fails to populate these

2. **Languages Override Detection**
   - Checks for modified `navigator.languages` getter
   - Detects non-native code in property descriptors

3. **Media Devices Check**
   - Verifies presence of media input devices
   - Headless browsers often have no devices

4. **Screen Dimensions Validation**
   - Detects invalid screen dimensions (0x0)
   - Common in headless environments

### Canvas & Audio Fingerprinting

1. **Canvas Fingerprinting**
   - Renders text and shapes on canvas
   - Detects blank or identical outputs (bot signature)
   - Stores hash for consistency checking

2. **Audio Context Fingerprinting**
   - Creates audio oscillator and analyzes processing
   - Detects fake or missing audio processing
   - Identifies headless browsers lacking audio support

### Implementation

```javascript
// In antibot-tracking.js
function detectAutomation() {
    const flags = [];
    
    // Playwright Stealth checks
    if (window.navigator.webdriver === false) {
        flags.push('playwright_stealth_webdriver_false');
    }
    
    // Puppeteer Stealth checks
    if (navigator.plugins.length === 0 && navigator.mimeTypes.length === 0) {
        flags.push('puppeteer_stealth_empty_plugins');
    }
    
    // Canvas fingerprinting
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    // ... render and analyze
    
    // Audio fingerprinting
    const audioContext = new AudioContext();
    // ... create oscillator and analyze
    
    return { isAutomated, flags, score };
}
```

## TLS/JA3 Fingerprinting

### What is JA3?

JA3 is a method for creating SSL/TLS client fingerprints that can uniquely identify clients, even when they use the same IP address. Our implementation creates a JA3-like fingerprint using:

1. **SSL/TLS Protocol Version** (`$_SERVER['SSL_PROTOCOL']`)
2. **Cipher Suite** (`$_SERVER['SSL_CIPHER']`)
3. **HTTP Header Order** - Browsers have consistent header ordering
4. **Accept Headers** - Distinct patterns per browser
5. **Client Hints** - Chrome-specific metadata
6. **Fetch Metadata** - Modern browser security headers

### Implementation

```php
function generate_ja3_fingerprint() {
    $components = [];
    
    // SSL/TLS info
    $components[] = $_SERVER['SSL_PROTOCOL'] ?? 'unknown';
    $components[] = $_SERVER['SSL_CIPHER'] ?? 'unknown';
    
    // Header ordering
    $header_order = [];
    foreach (array_keys(getallheaders()) as $header) {
        $header_order[] = strtolower(str_replace('-', '_', $header));
    }
    $components[] = implode(',', $header_order);
    
    // Accept headers
    $components[] = implode('|', [
        $_SERVER['HTTP_ACCEPT'] ?? '',
        $_SERVER['HTTP_ACCEPT_ENCODING'] ?? '',
        $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? ''
    ]);
    
    return hash('sha256', implode('||', $components));
}
```

### Session Enforcement

JA3 fingerprints are enforced as follows:

1. **First Visit** - Fingerprint is generated and stored
2. **Subsequent Visits** - Current fingerprint is compared to stored
3. **Mismatch Detection** - If fingerprints differ, session is invalidated
4. **Security Logging** - All mismatches are logged for investigation

This prevents:
- **Session Hijacking** - Attacker can't use stolen cookies from different client
- **Replay Attacks** - Replayed requests will have different TLS characteristics
- **Bot Rotation** - Bots cycling through IPs are detected by fingerprint changes

## Enhanced Session Binding

The system enforces three-factor session binding:

### 1. IP Subnet Binding

```php
function extract_subnet($ip) {
    // IPv4: first 3 octets (e.g., 192.168.1.0)
    // IPv6: first 4 segments
    return implode('.', array_slice(explode('.', $ip), 0, 3)) . '.0';
}
```

**Why subnets?** Allows for NAT and mobile IP changes within the same network while blocking cross-network hijacking.

### 2. TLS/JA3 Binding

Enforces that all requests in a session come from the same TLS client configuration.

**Configurable:**
```php
'enforce_tls_binding' => true,  // Set in config.php
'ja3_mismatch_penalty' => 100,   // Instant bot classification
```

### 3. User-Agent Hash Binding

Stores and verifies SHA-256 hash of User-Agent string.

**Prevents:**
- User-Agent rotation attacks
- Impersonation attempts
- Bot user-agent cycling

### Verification Flow

```php
function verify_session_binding($ip, $stored_fingerprint) {
    $mismatches = [];
    
    // Check subnet
    if ($current_subnet !== $stored_data['subnet']) {
        $mismatches[] = 'subnet_changed';
    }
    
    // Check JA3
    if ($current_ja3 !== $stored_data['ja3']) {
        $mismatches[] = 'ja3_mismatch';
    }
    
    // Check User-Agent
    if ($current_ua_hash !== $stored_data['user_agent_hash']) {
        $mismatches[] = 'user_agent_changed';
    }
    
    if (!empty($mismatches)) {
        // Log security event
        // Invalidate session
        return false;
    }
    
    return true;
}
```

## Behavioral Drift Detection

### Concept

Real humans naturally vary their behavior over time. Bots, especially scripted ones, exhibit static, unchanging patterns. The drift detector identifies this lack of natural variation.

### Detection Method

1. **Session Signatures** - Create behavioral signatures for each session:
   - Action count and types
   - Average timing and variance
   - Navigation patterns

2. **Similarity Scoring** - Compare consecutive sessions:
   - Action count similarity
   - Action type distribution
   - Timing pattern similarity

3. **Drift Analysis** - Calculate average similarity:
   - High similarity (>70%) = Static bot behavior
   - Low similarity = Natural human variation

### Implementation

```php
function detect_behavioral_drift($ip) {
    // Get all sessions for this IP
    $sessions = $behaviors[$ip]['sessions'];
    
    // Calculate signatures for each session
    $signatures = [];
    foreach ($sessions as $session) {
        $signature = [
            'action_count' => count($actions),
            'action_types' => $action_type_counts,
            'avg_timing' => $avg_interval,
            'timing_variance' => $variance
        ];
        $signatures[] = $signature;
    }
    
    // Compare consecutive sessions
    $similarity_scores = [];
    for ($i = 1; $i < count($signatures); $i++) {
        $similarity = calculate_similarity($signatures[$i-1], $signatures[$i]);
        $similarity_scores[] = $similarity;
    }
    
    // Check if behavior is too static
    $avg_similarity = array_sum($similarity_scores) / count($similarity_scores);
    
    if ($avg_similarity > 0.7) {
        return ['score' => 40, 'reasons' => ['No behavioral drift detected']];
    }
    
    return ['score' => 0, 'reasons' => []];
}
```

### Configuration

```php
'drift_detection' => [
    'enabled' => true,
    'max_pattern_similarity' => 0.7,  // Max similarity before flagging
    'min_sessions_for_drift' => 3,    // Need 3+ sessions
    'drift_penalty' => 40,             // Penalty score
],
```

## Dynamic Scoring System

### Non-Linear Amplification

The scoring system uses non-linear transformations to create decisive classifications:

```php
$apply_nonlinear = function($score) {
    if ($score < 20) {
        return $score * 0.5;      // Dampen low scores (likely human)
    } elseif ($score >= 20 && $score < 50) {
        return $score * 0.9;      // Keep medium scores linear
    } elseif ($score >= 50 && $score < 70) {
        return $score * 1.2;      // Amplify high scores (likely bot)
    } else {
        return min($score * 1.5, 100);  // Strong amplification (definite bot)
    }
};
```

### Dynamic Weights with Randomization

Weights are randomized on each evaluation to prevent reverse engineering:

```php
$base_weights = [
    'temporal' => 0.18,
    'noise' => 0.13,
    'semantics' => 0.13,
    'continuity' => 0.13,
    'mouse' => 0.18,
    'idealized' => 0.13,
    'drift' => 0.12
];

// Add ±10% random variance
foreach ($base_weights as $domain => $weight) {
    $variance = (mt_rand() / mt_getrandmax() * 2 - 1) * 0.1;
    $weights[$domain] = $weight * (1 + $variance);
}

// Normalize to sum to 1.0
$total = array_sum($weights);
foreach ($weights as $domain => $weight) {
    $weights[$domain] = $weight / $total;
}
```

### Randomized Thresholds

Thresholds vary on each run to make bot probing ineffective:

```php
$human_threshold = mt_rand(15, 25);  // Confident human: 15-25
$bot_threshold = mt_rand(50, 65);    // Likely bot: 50-65
```

### Seven Detection Domains

1. **Temporal Behavior (18%)** - Action timing patterns
2. **Interaction Noise (13%)** - Errors, corrections, hesitations
3. **UI Semantics (13%)** - Interaction with visual elements
4. **Session Continuity (13%)** - Navigation patterns
5. **Mouse Movements (18%)** - Entropy, jitter, smoothness
6. **Idealized Behavior (13%)** - Perfect patterns
7. **Behavioral Drift (12%)** - Static vs. dynamic behavior

## Shadow Enforcement Layer

### Concept

Instead of immediately blocking bots, the shadow layer:
- **Wastes bot resources** with delays and fake responses
- **Prevents reverse engineering** by not revealing detection
- **Gathers intelligence** on bot behavior patterns

### Modes

1. **Monitor Mode** - Log only, no enforcement
2. **Shadow Mode** - Silent degradation (default)
3. **Block Mode** - Immediate hard block

### Shadow Tactics

```php
'shadow_tactics' => [
    'silent_rate_limit' => true,       // Rate limit without alerting
    'response_delay_min' => 2000,      // 2-5 second delays
    'response_delay_max' => 5000,
    'fake_success_responses' => true,  // Return fake data
    'perpetual_loading' => true,       // Never-ending spinners
],
```

### Implementation

```php
function apply_shadow_enforcement($ip, $bot_score, $config) {
    $shadow_mode = $config['shadow_mode'] ?? 'shadow';
    
    if ($shadow_mode === 'monitor') {
        return null;  // Log only
    }
    
    if ($shadow_mode === 'block') {
        return 'block';  // Hard redirect
    }
    
    // Shadow tactics
    if ($tactics['silent_rate_limit']) {
        if (!check_shadow_rate_limit($ip)) {
            usleep(rand(2000, 5000) * 1000);  // Artificial delay
        }
    }
    
    // Return fake success based on bot score
    if ($bot_score >= 80) {
        return 'shadow_harsh';     // Completely fake data
    } elseif ($bot_score >= 60) {
        return 'shadow_moderate';  // Incomplete data
    }
    
    return 'shadow_light';         // Subtle degradation
}
```

### Fake Response Generation

```php
switch ($tactic_level) {
    case 'shadow_harsh':
        return [
            'success' => true,
            'data' => [
                'id' => 'fake_' . uniqid(),
                'items' => []  // Empty results
            ]
        ];
        
    case 'shadow_moderate':
        return [
            'success' => true,
            'data' => [
                'status' => 'processing',  // Perpetual processing
                'progress' => rand(10, 90)
            ]
        ];
}
```

## Configuration Guide

### Basic Setup

1. **Copy and customize config.php:**

```php
return [
    // API Keys
    'user_id' => 'your_neutrino_id',
    'api_key' => 'your_neutrino_key',
    'proxycheck_key' => 'your_proxycheck_key',
    
    // Generate unique salt
    'fingerprint_salt' => 'your_unique_salt_here',
    
    // Detection thresholds
    'threshold_human_min' => 15,
    'threshold_human_max' => 25,
    'threshold_bot_min' => 50,
    'threshold_bot_max' => 65,
];
```

2. **Set security mode:**

```php
'shadow_mode' => 'shadow',  // 'monitor', 'shadow', or 'block'
```

3. **Configure session binding:**

```php
'enforce_subnet_binding' => true,
'enforce_tls_binding' => true,
'enforce_ua_binding' => true,
```

### Advanced Configuration

#### Mouse Analysis Tuning

```php
'mouse_analysis' => [
    'min_entropy' => 0.3,           // Lower = stricter
    'curve_smoothness_max' => 0.9,  // Lower = stricter
    'min_jitter_variance' => 0.1,   // Higher = stricter
    'jitter_required' => true,
],
```

#### Drift Detection Tuning

```php
'drift_detection' => [
    'enabled' => true,
    'max_pattern_similarity' => 0.7,  // Lower = stricter
    'min_sessions_for_drift' => 3,
    'drift_penalty' => 40,
],
```

#### Shadow Enforcement Tuning

```php
'shadow_rate_limit' => 10,       // Max requests per window
'shadow_rate_window' => 60,      // Time window in seconds
'shadow_block_duration' => 300,  // Block duration (5 minutes)
```

### Security Best Practices

1. **Change Default Password**
   ```php
   // In admin-monitor.php
   define('ADMIN_PASSWORD', 'your_strong_password');
   ```

2. **Rotate Fingerprint Salt**
   ```bash
   openssl rand -hex 32
   ```
   Update in config.php monthly

3. **Monitor Security Logs**
   ```bash
   tail -f logs/security.log
   ```

4. **Review Access Patterns**
   - Access admin dashboard regularly
   - Look for anomalous patterns
   - Adjust thresholds based on false positives

5. **Keep Files Outside Web Root**
   - Move config.php outside public directory
   - Update path references
   - Set proper file permissions (600 for config)

## Testing

### Verify Detection Works

1. **Test with real browser:**
   - Should pass seamlessly (confident human)
   - No CAPTCHA shown

2. **Test with automation:**
   ```bash
   # Should be detected and blocked
   python -m playwright run test.py
   ```

3. **Check logs:**
   ```bash
   cat logs/automation.log
   cat logs/security.log
   ```

### Admin Dashboard

Access at: `http://your-site.com/admin-monitor.php`

Default credentials:
- Username: (none)
- Password: `admin123` (CHANGE THIS!)

Dashboard shows:
- Real-time statistics
- Detection rates
- Recent access attempts
- Bot characteristics
- Domain scores

## Maintenance

### Regular Tasks

1. **Weekly:**
   - Review admin dashboard
   - Check detection rates
   - Analyze false positives

2. **Monthly:**
   - Rotate fingerprint salt
   - Update thresholds if needed
   - Review security logs

3. **Quarterly:**
   - Update bot detection patterns
   - Review and adjust weights
   - Test with latest automation tools

### Troubleshooting

**High false positive rate:**
- Lower threshold_bot_min
- Increase threshold_human_max
- Disable strict checks (jitter_required)

**Bots getting through:**
- Lower threshold_bot_min
- Increase drift detection sensitivity
- Enable stricter TLS enforcement

**Performance issues:**
- Disable heavy checks (audio fingerprinting)
- Increase SEND_INTERVAL_MS
- Reduce MAX_MOUSE_MOVEMENTS

## Support

For issues or questions:
1. Check logs: `logs/antibot.log` and `logs/security.log`
2. Review admin dashboard for patterns
3. Test with browser developer tools open
4. Verify PHP version >= 7.4

## License

This anti-bot system is provided as-is for security purposes. Use responsibly and in compliance with applicable laws and regulations.
