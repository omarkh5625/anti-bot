#!/usr/bin/env php
<?php
/**
 * Bot Simulation Test Script
 * 
 * This script simulates bot behavior to test the anti-bot detection system.
 * It will make requests that exhibit bot-like characteristics.
 */

echo "=== Anti-Bot Detection Test - Bot Simulation ===\n\n";

// Configuration
$base_url = 'http://localhost:8000'; // Adjust if needed
$test_page = 'antibot.php';

// Simulate bot behavior by making rapid requests without proper headers
echo "Test 1: Rapid Sequential Requests (Bot-like timing)\n";
echo "Making 5 rapid requests...\n";

for ($i = 1; $i <= 5; $i++) {
    echo "  Request $i... ";
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "$base_url/$test_page");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_COOKIEJAR, '/tmp/bot_cookies.txt');
    curl_setopt($ch, CURLOPT_COOKIEFILE, '/tmp/bot_cookies.txt');
    
    // Bot-like headers (minimal, automated)
    curl_setopt($ch, CURLOPT_USERAGENT, 'Python-urllib/3.9 (bot-test)');
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Accept: */*',
    ]);
    
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    echo "HTTP $http_code\n";
    
    // Bot-like behavior: no delay between requests
    usleep(50000); // 50ms - very fast (bot-like)
}

echo "\nTest 2: Request without JavaScript execution simulation\n";
echo "Making request with bot user agent...\n";

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, "$base_url/$test_page");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);

// Clear bot-like user agent
curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (compatible; TestBot/1.0; +http://example.com/bot)');

$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

echo "Response HTTP Code: $http_code\n";

echo "\n=== Test Complete ===\n";
echo "\nTo see results:\n";
echo "1. Open admin-monitor.php in your browser\n";
echo "2. Look for entries with 'bot' verdict or high bot scores\n";
echo "3. The rapid requests and bot user agent should trigger detection\n";
echo "\nNote: For more realistic bot simulation, use Selenium or Puppeteer\n";
echo "which will trigger automation property detection.\n";
