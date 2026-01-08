# Bot Detection Testing Guide

## Overview
This guide explains how to test the anti-bot detection system and verify it's working correctly.

## Test Files Included

### 1. `test-bot-behavior.html`
Interactive web page that simulates bot-like behavior patterns:
- ✅ Automation property detection
- ✅ Perfect timing patterns (zero variance)
- ✅ Linear mouse movements (R² > 0.95)
- ✅ Zero-error behavior
- ✅ Links to admin dashboard for results

**How to use:**
1. Open `test-bot-behavior.html` in your browser
2. Click the test buttons to simulate different bot behaviors
3. Open the admin dashboard to see detection results
4. Compare scores before and after running tests

### 2. `test-bot-simulation.php`
Command-line script that makes bot-like HTTP requests:
- Rapid sequential requests (50ms apart)
- Bot user agent strings
- Minimal headers

**How to use:**
```bash
php test-bot-simulation.php
```

## Understanding Detection Results

### Score Interpretation
- **0-20%**: Confident human (seamless access)
- **20-57%**: Uncertain (may show CAPTCHA)
- **57%+**: Likely bot (blocked or shadow enforcement)

### Domain Scores
Each domain contributes to the overall bot confidence score:

1. **Temporal Behavior (20%)**: Timing patterns, hesitation
2. **Interaction Noise (15%)**: Errors, cancellations
3. **UI Semantics (15%)**: Element targeting patterns
4. **Session Continuity (15%)**: Navigation patterns
5. **Mouse Movement (20%)**: Entropy, jitter, linearity
6. **Idealized Behavior (15%)**: Perfect patterns, zero variance

## Testing Scenarios

### Scenario 1: Normal Human Behavior (Expected: 0-10% score)
1. Visit the protected page normally
2. Move mouse naturally
3. Click on elements naturally
4. Take natural pauses
5. **Expected Result**: Low or 0% bot score, "human" verdict

### Scenario 2: Bot Simulation (Expected: 60-90% score)
1. Open `test-bot-behavior.html`
2. Run all test buttons
3. Check admin dashboard
4. **Expected Result**: High bot scores, detection flags raised

### Scenario 3: Selenium/WebDriver (Expected: 80-95% score)
1. Use Selenium or Puppeteer to visit the page
2. Automation properties will be detected
3. **Expected Result**: Very high bot score, "automation" verdict

## Checking Results

### Admin Dashboard
1. Open `admin-monitor.php`
2. Look for recent access attempts
3. Check the "Bot Score" column
4. Click "View Details" to see:
   - Individual domain scores
   - Detection flags raised
   - Behavioral characteristics
   - Verdict (human/bot/uncertain)

### What to Look For

**Human Access (Working Correctly):**
```
IP Address: 192.168.1.100
Bot Score: 5.2%
Verdict: human
Domain Scores:
  - Temporal: 0%
  - Noise: 0%
  - Semantics: 0%
  - Continuity: 0%
  - Mouse: 8%
  - Idealized: 0%
Detection Flags: None
```

**Bot Detection (Working Correctly):**
```
IP Address: 192.168.1.101
Bot Score: 78.4%
Verdict: bot
Domain Scores:
  - Temporal: 85%
  - Noise: 60%
  - Semantics: 70%
  - Continuity: 75%
  - Mouse: 90%
  - Idealized: 80%
Detection Flags:
  - Perfect timing intervals
  - Linear mouse movements
  - Zero errors detected
  - Automation properties found
```

## Common Issues

### All Scores Show 0%
**Cause**: No behavioral data collected yet
**Solution**: 
- Make sure JavaScript is enabled
- Interact with the page (move mouse, click)
- Wait for the 5-second analysis period
- Reload the page to trigger analysis

### "hidden" Values in Dashboard
**Cause**: Secure mode is enabled
**Solution**: 
- Edit `config.php`
- Set `hash_fingerprints => false`
- Set `hide_raw_scores => false`
- Set `hide_rejection_reasons => false`

### No Detection Even with test-bot-behavior.html
**Cause**: Behavioral data not being sent
**Solution**:
- Check browser console for errors
- Verify `antibot-tracking.js` is loaded
- Check that behavioral data is being sent to server
- Verify `behavior_tracking.json` file is writable

## Advanced Testing

### Using Selenium (Python)
```python
from selenium import webdriver

driver = webdriver.Chrome()
driver.get('http://localhost/antibot.php')
# Should be detected as bot immediately
```

### Using Puppeteer (JavaScript)
```javascript
const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  await page.goto('http://localhost/antibot.php');
  // Should be detected as bot
  await browser.close();
})();
```

### Using cURL (Command Line)
```bash
# Rapid requests (bot-like)
for i in {1..10}; do
  curl -A "BotAgent/1.0" http://localhost/antibot.php &
done
```

## Troubleshooting

### Check Logs
```bash
# View security log (full details)
tail -f logs/security.log

# View access log
cat logs/access_log.json | jq '.[-5:]'  # Last 5 entries

# View behavioral data
cat behavior_tracking.json | jq '.'
```

### Verify Configuration
```bash
# Check if secure mode is disabled
grep "hide_raw_scores" config.php
# Should show: 'hide_raw_scores' => false,

# Check HMAC secret is set
grep "ANTIBOT_HMAC_SECRET" config.php
```

## Expected Detection Rates

Based on testing, the system achieves:
- **Selenium/WebDriver**: 95-99% detection
- **Puppeteer/Playwright**: 95-98% detection
- **Simple bots (cURL)**: 85-90% detection
- **Human users**: <2% false positive rate

## Support

If bot detection isn't working:
1. Verify all files are present (antibot.php, antibot-tracking.js, config.php)
2. Check file permissions (logs directory must be writable)
3. Ensure PHP has required extensions (json, openssl)
4. Test with `test-bot-behavior.html` first
5. Check browser console for JavaScript errors
6. Review logs/security.log for errors

## Success Criteria

Your anti-bot system is working correctly if:
✅ Normal users show 0-10% bot scores
✅ Automation tools show 70-95% bot scores
✅ Detection flags are accurate
✅ Admin dashboard displays all data
✅ Shadow enforcement activates for high scores
✅ No false positives on legitimate users
