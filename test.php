<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Anti-Bot Test Page</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            background: #f5f7fa;
        }
        .success {
            background: #d1fae5;
            border: 2px solid #10b981;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        .info {
            background: #e0e7ff;
            border: 2px solid #667eea;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        h1 { color: #333; }
        h2 { color: #667eea; }
        .cookie-info {
            background: white;
            padding: 15px;
            border-radius: 8px;
            margin: 10px 0;
        }
        .cookie-info code {
            background: #f3f4f6;
            padding: 2px 6px;
            border-radius: 4px;
            color: #e11d48;
        }
        .links {
            margin-top: 30px;
        }
        .links a {
            display: inline-block;
            margin: 10px 10px 10px 0;
            padding: 12px 24px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-weight: bold;
        }
        .links a:hover {
            background: #5568d3;
        }
    </style>
</head>
<body>
    <?php
    // Include anti-bot protection
    require_once 'antibot.php';
    ?>
    
    <div class="success">
        <h1>✅ Anti-Bot Protection Successful!</h1>
        <p>You have successfully passed the anti-bot verification.</p>
    </div>
    
    <div class="info">
        <h2>🔒 Your Session Information</h2>
        
        <div class="cookie-info">
            <strong>IP Address:</strong> <code><?php echo htmlspecialchars(get_client_ip()); ?></code>
        </div>
        
        <div class="cookie-info">
            <strong>Session Status:</strong> 
            <?php if (isset($_COOKIE['js_verified'])): ?>
                <code style="color: #10b981;">✅ Verified</code>
            <?php else: ?>
                <code style="color: #ef4444;">❌ Not Verified</code>
            <?php endif; ?>
        </div>
        
        <div class="cookie-info">
            <strong>Fingerprint:</strong> 
            <?php if (isset($_COOKIE['fp_hash'])): ?>
                <code><?php echo substr($_COOKIE['fp_hash'], 0, 16); ?>...</code>
            <?php else: ?>
                <code>None</code>
            <?php endif; ?>
        </div>
        
        <div class="cookie-info">
            <strong>User Agent:</strong><br>
            <code style="font-size: 11px; word-break: break-all;">
                <?php echo htmlspecialchars($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'); ?>
            </code>
        </div>
    </div>
    
    <div class="info">
        <h2>📊 How It Works</h2>
        <ul>
            <li><strong>First Visit:</strong> Shows "Checking your connection security..." for 5 seconds</li>
            <li><strong>Behavioral Analysis:</strong> Tracks mouse movements, clicks, and timing patterns</li>
            <li><strong>Classification:</strong>
                <ul>
                    <li>< 20% bot score: Direct access (confident human)</li>
                    <li>20-57% bot score: CAPTCHA challenge (uncertain)</li>
                    <li>> 57% bot score: Blocked (likely bot)</li>
                </ul>
            </li>
            <li><strong>Dynamic Fingerprints:</strong> Hourly-rotating cryptographic fingerprints</li>
            <li><strong>Session Binding:</strong> Sessions tied to network subnet</li>
        </ul>
    </div>
    
    <div class="links">
        <h2>🔗 Quick Links</h2>
        <a href="admin-monitor.php">📊 Admin Dashboard</a>
        <a href="?clear_session=1">🔄 Clear Session</a>
    </div>
    
    <?php
    // Handle clear session server-side
    if (isset($_GET['clear_session'])) {
        setcookie('js_verified', '', time() - 3600, '/');
        setcookie('fp_hash', '', time() - 3600, '/');
        setcookie('analysis_done', '', time() - 3600, '/');
        echo '<script>setTimeout(() => location.href = "test.php", 1000);</script>';
    }
    ?>
    
    <div style="margin-top: 30px; padding: 20px; background: white; border-radius: 8px; font-size: 14px; color: #666;">
        <strong>Test Instructions:</strong>
        <ol>
            <li>Click "Clear Session" to test the verification flow again</li>
            <li>Open in incognito/private mode to simulate new visitor</li>
            <li>Try automated tools (Selenium) to test bot detection</li>
            <li>Check Admin Dashboard to see detection statistics</li>
        </ol>
    </div>
</body>
</html>
