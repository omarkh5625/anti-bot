<?php
// Simple test script to diagnose admin-monitor.php issues
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);

echo "Step 1: PHP is working<br>\n";

// Try to start session
try {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
        echo "Step 2: Session started successfully<br>\n";
    }
} catch (Exception $e) {
    die("Session error: " . $e->getMessage());
}

// Check if logs directory can be created
$log_dir = __DIR__ . '/logs';
if (!is_dir($log_dir)) {
    if (@mkdir($log_dir, 0755, true)) {
        echo "Step 3: Created logs directory<br>\n";
    } else {
        echo "Step 3: Could not create logs directory<br>\n";
    }
} else {
    echo "Step 3: Logs directory exists<br>\n";
}

// Check if we can write to logs directory
$test_file = $log_dir . '/test.txt';
if (@file_put_contents($test_file, 'test')) {
    echo "Step 4: Can write to logs directory<br>\n";
    @unlink($test_file);
} else {
    echo "Step 4: Cannot write to logs directory<br>\n";
}

// Try to include admin-monitor.php
echo "Step 5: About to include admin-monitor.php<br>\n";
flush();

// This will show where the error occurs
include __DIR__ . '/admin-monitor.php';
