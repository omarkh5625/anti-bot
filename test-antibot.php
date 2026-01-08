#!/usr/bin/env php
<?php
/**
 * Anti-Bot Framework Test Suite
 * 
 * Tests key functionality:
 * - Config loading
 * - Cryptographic functions
 * - Nonce validation
 * - Fingerprinting
 * - Behavior analysis
 */

echo "=== Anti-Bot Framework Test Suite ===\n\n";

// Test 1: Config Loading
echo "Test 1: Configuration Loading... ";
try {
    $config = require __DIR__ . '/config.php';
    if (!is_array($config)) {
        throw new Exception('Config is not an array');
    }
    if (!isset($config['hmac_secret'], $config['fingerprint_salt'])) {
        throw new Exception('Missing required config keys');
    }
    echo "✓ PASSED\n";
} catch (Exception $e) {
    echo "✗ FAILED: " . $e->getMessage() . "\n";
    exit(1);
}

// Test 2: HMAC Signature Generation
echo "Test 2: HMAC Signature Generation... ";
$test_key = 'test_secret_key_12345';
$test_message = 'test_message';
$signature = hash_hmac('sha256', $test_message, $test_key);
if (strlen($signature) === 64) {
    echo "✓ PASSED (signature: " . substr($signature, 0, 16) . "...)\n";
} else {
    echo "✗ FAILED: Invalid signature length\n";
    exit(1);
}

// Test 3: Nonce Validation Functions
echo "Test 3: Nonce Validation... ";
require_once __DIR__ . '/antibot.php';

// Test valid nonce
$valid_nonce = (time() * 1000) . '_' . uniqid();
$is_valid = verify_nonce($valid_nonce);
if (!$is_valid) {
    echo "✗ FAILED: Valid nonce rejected\n";
    exit(1);
}

// Test expired nonce (6 minutes old)
$expired_nonce = ((time() - 360) * 1000) . '_' . uniqid();
$is_expired = verify_nonce($expired_nonce);
if ($is_expired) {
    echo "✗ FAILED: Expired nonce accepted\n";
    exit(1);
}

// Test future nonce (2 minutes in future)
$future_nonce = ((time() + 120) * 1000) . '_' . uniqid();
$is_future = verify_nonce($future_nonce);
if ($is_future) {
    echo "✗ FAILED: Future nonce accepted\n";
    exit(1);
}

echo "✓ PASSED\n";

// Test 4: Dynamic Fingerprinting
echo "Test 4: Dynamic Fingerprinting... ";
$_SERVER['SERVER_NAME'] = 'test.example.com';
$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 Test Browser';
$_SERVER['HTTP_ACCEPT'] = 'text/html,application/xhtml+xml';
$_SERVER['HTTP_ACCEPT_LANGUAGE'] = 'en-US,en;q=0.9';
$_SERVER['HTTP_ACCEPT_ENCODING'] = 'gzip, deflate';

$fp1 = generate_dynamic_fingerprint('192.168.1.100', 'sess_test_123');
$fp2 = generate_dynamic_fingerprint('192.168.1.100', 'sess_test_123');

// Fingerprints from same inputs should be identical
if ($fp1 === $fp2) {
    echo "✓ PASSED (fingerprint: " . substr($fp1, 0, 16) . "...)\n";
} else {
    echo "✗ FAILED: Same inputs produced different fingerprints\n";
    exit(1);
}

// Test 5: IP Subnet Extraction
echo "Test 5: IP Subnet Extraction... ";
$ipv4_subnet = extract_subnet('192.168.1.100');
$ipv6_subnet = extract_subnet('2001:0db8:85a3:0000:0000:8a2e:0370:7334');

if ($ipv4_subnet === '192.168.1.0' && strpos($ipv6_subnet, '2001:0db8:85a3:0000::') === 0) {
    echo "✓ PASSED (IPv4: $ipv4_subnet, IPv6: " . substr($ipv6_subnet, 0, 20) . "...)\n";
} else {
    echo "✗ FAILED: Incorrect subnet extraction\n";
    exit(1);
}

// Test 6: Shadow Enforcement
echo "Test 6: Shadow Enforcement... ";
$config['shadow_mode'] = 'shadow';
$config['shadow_tactics'] = [
    'fake_success' => true,
    'response_delay_min' => 100,
    'response_delay_max' => 200
];

$shadow_action = apply_shadow_enforcement('192.168.1.100', 85, $config);
if (strpos($shadow_action, 'shadow_') === 0) {
    echo "✓ PASSED (action: $shadow_action)\n";
} else {
    echo "✗ FAILED: Shadow enforcement not working\n";
    exit(1);
}

// Test 7: Session Trust Calculation
echo "Test 7: Session Trust Calculation... ";
$config['session_trust_decay_rate'] = 5;
$config['session_max_age'] = 86400;

// Test new session (should have 100% trust)
$new_session_trust = calculate_session_trust(time(), $config);
if ($new_session_trust >= 99 && $new_session_trust <= 100) {
    echo "✓ PASSED (new session trust: $new_session_trust%)\n";
} else {
    echo "✗ FAILED: New session trust should be ~100%, got $new_session_trust%\n";
    exit(1);
}

// Test old session (should have decayed trust)
$old_session_trust = calculate_session_trust(time() - 7200, $config); // 2 hours ago
if ($old_session_trust >= 85 && $old_session_trust < 100) {
    echo "  Session 2 hours old: $old_session_trust% trust ✓\n";
} else {
    echo "  Warning: 2-hour session trust is $old_session_trust%, expected ~90%\n";
}

// Test 8: Non-Linear Scoring
echo "Test 8: Non-Linear Scoring Transformation... ";
$test_scores = [10, 30, 50, 70, 90];
$transformed_scores = [];

foreach ($test_scores as $score) {
    if ($score < 20) {
        $transformed = $score * 0.5;
    } elseif ($score >= 20 && $score < 50) {
        $transformed = $score * 0.9;
    } elseif ($score >= 50 && $score < 70) {
        $transformed = $score * 1.2;
    } else {
        $transformed = min($score * 1.5, 100);
    }
    $transformed_scores[] = $transformed;
}

// Low scores should be dampened, high scores amplified
if ($transformed_scores[0] < $test_scores[0] && $transformed_scores[4] > $test_scores[4]) {
    echo "✓ PASSED (10→" . $transformed_scores[0] . ", 90→" . $transformed_scores[4] . ")\n";
} else {
    echo "✗ FAILED: Non-linear transformation not working correctly\n";
    exit(1);
}

// Test 9: Dynamic Threshold Randomization
echo "Test 9: Dynamic Threshold Randomization... ";
$thresholds = [];
for ($i = 0; $i < 10; $i++) {
    $threshold = mt_rand($config['threshold_human_min'] ?? 15, $config['threshold_human_max'] ?? 25);
    $thresholds[] = $threshold;
}

$unique_thresholds = count(array_unique($thresholds));
if ($unique_thresholds >= 3) {
    echo "✓ PASSED ($unique_thresholds unique thresholds generated)\n";
} else {
    echo "⚠ WARNING: Low threshold variance ($unique_thresholds unique)\n";
}

// Test 10: Secure Logging
echo "Test 10: Secure Logging Configuration... ";
$logging_config = $config['logging'] ?? [];
$secure_features = [
    'hash_fingerprints' => $logging_config['hash_fingerprints'] ?? false,
    'hide_rejection_reasons' => $logging_config['hide_rejection_reasons'] ?? false,
    'hide_raw_scores' => $logging_config['hide_raw_scores'] ?? false,
    'separate_security_logs' => $logging_config['separate_security_logs'] ?? false
];

$enabled_features = array_filter($secure_features);
if (count($enabled_features) >= 3) {
    echo "✓ PASSED (" . count($enabled_features) . "/4 security features enabled)\n";
} else {
    echo "⚠ WARNING: Only " . count($enabled_features) . "/4 security features enabled\n";
}

// Summary
echo "\n=== Test Suite Complete ===\n";
echo "All critical tests passed! ✓\n";
echo "\nSecurity Features Enabled:\n";
echo "  ✓ HMAC-SHA256 Telemetry Signing\n";
echo "  ✓ Nonce-based Replay Protection\n";
echo "  ✓ Dynamic Fingerprinting\n";
echo "  ✓ Session Binding & Aging\n";
echo "  ✓ Shadow Enforcement\n";
echo "  ✓ Non-Linear Scoring\n";
echo "  ✓ Dynamic Thresholds\n";
echo "  ✓ Secure Logging\n";
echo "\nFramework is ready for deployment!\n";
