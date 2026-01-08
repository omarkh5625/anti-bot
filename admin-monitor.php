<?php
/**
 * Anti-Bot Admin Monitoring Dashboard
 * 
 * Displays comprehensive statistics and history of all access attempts:
 * - Real-time statistics (Human, Bot, Uncertain)
 * - Complete access history with bot characteristics
 * - Detection domain scores for each visitor
 * - Automation flags and behavioral patterns
 * - Charts and visual analytics
 * 
 * Security: Password protected admin panel
 */

// CRITICAL: Enable ALL error reporting at the very first line
@ini_set('display_errors', '1');
@ini_set('display_startup_errors', '1');
@error_reporting(E_ALL);
@ini_set('log_errors', '1');

// Set a custom error handler to catch everything
set_error_handler(function($errno, $errstr, $errfile, $errline) {
    echo "<div style='background: #f44336; color: white; padding: 20px; margin: 10px; border-radius: 5px;'>";
    echo "<h3>PHP Error Detected:</h3>";
    echo "<p><strong>Error:</strong> " . htmlspecialchars($errstr) . "</p>";
    echo "<p><strong>File:</strong> " . htmlspecialchars($errfile) . "</p>";
    echo "<p><strong>Line:</strong> " . $errline . "</p>";
    echo "</div>";
    return true;
});

// Set exception handler
set_exception_handler(function($e) {
    echo "<div style='background: #f44336; color: white; padding: 20px; margin: 10px; border-radius: 5px;'>";
    echo "<h3>PHP Exception:</h3>";
    echo "<p><strong>Message:</strong> " . htmlspecialchars($e->getMessage()) . "</p>";
    echo "<p><strong>File:</strong> " . htmlspecialchars($e->getFile()) . "</p>";
    echo "<p><strong>Line:</strong> " . $e->getLine() . "</p>";
    echo "<p><strong>Trace:</strong><pre>" . htmlspecialchars($e->getTraceAsString()) . "</pre></p>";
    echo "</div>";
});

// Catch fatal errors
register_shutdown_function(function() {
    $error = error_get_last();
    if ($error !== null && in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR])) {
        echo "<div style='background: #f44336; color: white; padding: 20px; margin: 10px; border-radius: 5px;'>";
        echo "<h3>Fatal PHP Error:</h3>";
        echo "<p><strong>Error:</strong> " . htmlspecialchars($error['message']) . "</p>";
        echo "<p><strong>File:</strong> " . htmlspecialchars($error['file']) . "</p>";
        echo "<p><strong>Line:</strong> " . $error['line'] . "</p>";
        echo "</div>";
    }
});

// Start session with error handling
if (session_status() === PHP_SESSION_NONE) {
    @session_start();
}

// ==================== CONFIGURATION ====================

// Admin password (CHANGE THIS!)
// ⚠️ SECURITY WARNING: This default password is INSECURE!
// ⚠️ You MUST change this to a strong password in production!
// ⚠️ Consider using password_hash() and password_verify() for production use
define('ADMIN_PASSWORD', 'admin123'); // Default: admin123 - CHANGE IMMEDIATELY!

// File paths
define('BEHAVIOR_FILE', __DIR__ . '/behavior_tracking.json');
define('AUTOMATION_LOG', __DIR__ . '/logs/automation.log');
define('ACCESS_LOG', __DIR__ . '/logs/access_log.json');
define('LOG_DIR', __DIR__ . '/logs');

// ==================== AUTO-CREATE FILES & DIRECTORIES ====================

// Create logs directory if it doesn't exist
if (!file_exists(LOG_DIR)) {
    @mkdir(LOG_DIR, 0755, true);
}

// Create access log file if it doesn't exist
if (!file_exists(ACCESS_LOG)) {
    @file_put_contents(ACCESS_LOG, json_encode([], JSON_PRETTY_PRINT));
    @chmod(ACCESS_LOG, 0644);
}

// Create automation log file if it doesn't exist
if (!file_exists(AUTOMATION_LOG)) {
    @file_put_contents(AUTOMATION_LOG, '');
    @chmod(AUTOMATION_LOG, 0644);
}

// Create behavior tracking file if it doesn't exist
if (!file_exists(BEHAVIOR_FILE)) {
    @file_put_contents(BEHAVIOR_FILE, json_encode([], JSON_PRETTY_PRINT));
    @chmod(BEHAVIOR_FILE, 0644);
}

// ==================== AUTHENTICATION ====================

// Handle login
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password'])) {
    // Use hash_equals() to prevent timing attacks
    if (hash_equals(ADMIN_PASSWORD, $_POST['password'])) {
        $_SESSION['admin_logged_in'] = true;
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    } else {
        $login_error = 'Incorrect password';
    }
}

// Handle logout
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// Check authentication
if (!isset($_SESSION['admin_logged_in']) || !$_SESSION['admin_logged_in']) {
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Login - Anti-Bot Monitoring Dashboard</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .login-box {
                background: white;
                padding: 40px;
                border-radius: 15px;
                box-shadow: 0 10px 40px rgba(0,0,0,0.2);
                width: 350px;
            }
            h1 {
                text-align: center;
                color: #667eea;
                margin-bottom: 30px;
                font-size: 24px;
            }
            input[type="password"] {
                width: 100%;
                padding: 12px;
                border: 2px solid #e0e0e0;
                border-radius: 8px;
                font-size: 16px;
                margin-bottom: 20px;
                transition: border-color 0.3s;
            }
            input[type="password"]:focus {
                outline: none;
                border-color: #667eea;
            }
            button {
                width: 100%;
                padding: 12px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                border: none;
                border-radius: 8px;
                font-size: 16px;
                font-weight: bold;
                cursor: pointer;
                transition: transform 0.2s;
            }
            button:hover {
                transform: translateY(-2px);
            }
            .error {
                background: #fee;
                color: #c33;
                padding: 10px;
                border-radius: 5px;
                margin-bottom: 15px;
                text-align: center;
            }
            .icon {
                text-align: center;
                font-size: 48px;
                margin-bottom: 20px;
            }
        </style>
    </head>
    <body>
        <div class="login-box">
            <div class="icon">🔒</div>
            <h1>Anti-Bot Monitoring Dashboard</h1>
            <?php if (isset($login_error)): ?>
                <div class="error"><?= htmlspecialchars($login_error) ?></div>
            <?php endif; ?>
            <form method="POST">
                <input type="password" name="password" placeholder="Password" required autofocus>
                <button type="submit">Login</button>
            </form>
        </div>
    </body>
    </html>
    <?php
    exit;
}

// ==================== DATA LOADING FUNCTIONS ====================
// (Files and directories are auto-created at the top of the script)

/**
 * Load all access logs
 */
function load_access_logs() {
    if (!file_exists(ACCESS_LOG)) {
        return [];
    }
    $data = @file_get_contents(ACCESS_LOG);
    if ($data === false) {
        error_log('Anti-bot Admin: Failed to read access log file at ' . ACCESS_LOG);
        return [];
    }
    return json_decode($data, true) ?: [];
}

/**
 * Load behavior tracking data
 */
if (!function_exists('load_behavior_data')) {
    function load_behavior_data() {
        if (!file_exists(BEHAVIOR_FILE)) {
            return [];
        }
        $data = @file_get_contents(BEHAVIOR_FILE);
        if ($data === false) {
            error_log('Anti-bot Admin: Failed to read behavior file at ' . BEHAVIOR_FILE);
            return [];
        }
        return json_decode($data, true) ?: [];
    }
}

/**
 * Load automation detection logs
 */
function load_automation_logs() {
    if (!file_exists(AUTOMATION_LOG)) {
        return [];
    }
    $lines = file(AUTOMATION_LOG, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $logs = [];
    foreach ($lines as $line) {
        $parts = explode(' | ', $line);
        if (count($parts) >= 4) {
            $logs[] = [
                'timestamp' => $parts[0],
                'type' => $parts[1],
                'ip' => str_replace('IP: ', '', $parts[2]),
                'flags' => str_replace('Flags: ', '', $parts[3]),
                'score' => isset($parts[4]) ? str_replace('Score: ', '', $parts[4]) : 'N/A'
            ];
        }
    }
    return array_reverse($logs); // Most recent first
}

/**
 * Calculate statistics from access logs
 */
function calculate_statistics($logs) {
    $stats = [
        'total' => 0,
        'humans' => 0,
        'bots' => 0,
        'uncertain' => 0,
        'blocked_automation' => 0,
        'today' => 0,
        'this_hour' => 0
    ];
    
    $now = time();
    $today_start = strtotime('today');
    $hour_start = strtotime('-1 hour');
    
    foreach ($logs as $log) {
        $stats['total']++;
        
        $timestamp = strtotime($log['timestamp']);
        if ($timestamp >= $today_start) {
            $stats['today']++;
        }
        if ($timestamp >= $hour_start) {
            $stats['this_hour']++;
        }
        
        if (isset($log['verdict'])) {
            if ($log['verdict'] === 'human') {
                $stats['humans']++;
            } elseif ($log['verdict'] === 'bot') {
                $stats['bots']++;
            } elseif ($log['verdict'] === 'uncertain') {
                $stats['uncertain']++;
            } elseif ($log['verdict'] === 'automation') {
                $stats['blocked_automation']++;
            }
        }
    }
    
    return $stats;
}

/**
 * Get recent access attempts (last N)
 */
function get_recent_attempts($limit = 50) {
    $logs = load_access_logs();
    return array_slice(array_reverse($logs), 0, $limit);
}

// ==================== LOAD DATA ====================

$access_logs = load_access_logs();
$behavior_data = load_behavior_data();
$automation_logs = load_automation_logs();
$statistics = calculate_statistics($access_logs);
$recent_attempts = get_recent_attempts(50);

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Anti-Bot Monitoring Dashboard - Statistics & Logs</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f7fa;
            padding: 20px;
            direction: ltr;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 15px;
            margin-bottom: 30px;
            box-shadow: 0 5px 20px rgba(102, 126, 234, 0.3);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .header h1 {
            font-size: 32px;
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .logout-btn {
            background: rgba(255,255,255,0.2);
            color: white;
            padding: 10px 20px;
            border: 2px solid white;
            border-radius: 8px;
            text-decoration: none;
            font-weight: bold;
            transition: all 0.3s;
        }
        
        .logout-btn:hover {
            background: white;
            color: #667eea;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
            transition: transform 0.3s, box-shadow 0.3s;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 5px 20px rgba(0,0,0,0.15);
        }
        
        .stat-card .icon {
            font-size: 36px;
            margin-bottom: 10px;
        }
        
        .stat-card .label {
            color: #666;
            font-size: 14px;
            margin-bottom: 8px;
        }
        
        .stat-card .value {
            font-size: 36px;
            font-weight: bold;
            color: #333;
        }
        
        .stat-card.humans .value { color: #10b981; }
        .stat-card.bots .value { color: #ef4444; }
        .stat-card.uncertain .value { color: #f59e0b; }
        .stat-card.total .value { color: #667eea; }
        
        .section {
            background: white;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
            margin-bottom: 30px;
        }
        
        .section h2 {
            color: #333;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 2px solid #e0e0e0;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .access-table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .access-table th,
        .access-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e0e0e0;
        }
        
        .access-table th {
            background: #f5f7fa;
            font-weight: bold;
            color: #666;
            position: sticky;
            top: 0;
        }
        
        .access-table tr:hover {
            background: #f9fafb;
        }
        
        .badge {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .badge.human {
            background: #d1fae5;
            color: #065f46;
        }
        
        .badge.bot {
            background: #fee2e2;
            color: #991b1b;
        }
        
        .badge.uncertain {
            background: #fef3c7;
            color: #92400e;
        }
        
        .badge.automation {
            background: #fecaca;
            color: #7f1d1d;
        }
        
        .score-badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 15px;
            font-size: 13px;
            font-weight: bold;
            background: #e0e7ff;
            color: #3730a3;
        }
        
        .details-btn {
            background: #667eea;
            color: white;
            border: none;
            padding: 6px 12px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 12px;
            transition: background 0.3s;
        }
        
        .details-btn:hover {
            background: #5568d3;
        }
        
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.7);
            z-index: 1000;
            overflow-y: auto;
        }
        
        .modal-content {
            background: white;
            margin: 50px auto;
            padding: 30px;
            border-radius: 15px;
            max-width: 800px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
        }
        
        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 25px;
            padding-bottom: 15px;
            border-bottom: 2px solid #e0e0e0;
        }
        
        .modal-header h2 {
            color: #667eea;
            margin: 0;
            padding: 0;
            border: none;
        }
        
        .close-btn {
            background: #ef4444;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            font-weight: bold;
        }
        
        .close-btn:hover {
            background: #dc2626;
        }
        
        .details-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 20px;
            margin-bottom: 25px;
        }
        
        .detail-item {
            background: #f9fafb;
            padding: 15px;
            border-radius: 8px;
            border-right: 4px solid #667eea;
        }
        
        .detail-label {
            color: #666;
            font-size: 13px;
            margin-bottom: 5px;
        }
        
        .detail-value {
            color: #333;
            font-size: 16px;
            font-weight: bold;
        }
        
        .domain-scores {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
            margin-bottom: 25px;
        }
        
        .domain-card {
            background: #f9fafb;
            padding: 15px;
            border-radius: 8px;
        }
        
        .domain-name {
            color: #666;
            font-size: 13px;
            margin-bottom: 8px;
        }
        
        .domain-score {
            font-size: 28px;
            font-weight: bold;
            color: #667eea;
        }
        
        .domain-contribution {
            font-size: 13px;
            color: #999;
            margin-top: 5px;
        }
        
        .flags-list {
            background: #fef3c7;
            padding: 15px;
            border-radius: 8px;
            border-right: 4px solid #f59e0b;
        }
        
        .flags-list h3 {
            color: #92400e;
            font-size: 16px;
            margin-bottom: 10px;
        }
        
        .flags-list ul {
            list-style: none;
            padding: 0;
        }
        
        .flags-list li {
            padding: 5px 0;
            color: #78350f;
        }
        
        .flags-list li::before {
            content: "⚠️ ";
            margin-left: 8px;
        }
        
        .refresh-btn {
            position: fixed;
            bottom: 30px;
            left: 30px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 15px 25px;
            border-radius: 50px;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4);
            transition: transform 0.3s;
        }
        
        .refresh-btn:hover {
            transform: translateY(-3px);
        }
        
        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: #999;
        }
        
        .empty-state .icon {
            font-size: 64px;
            margin-bottom: 20px;
        }
        
        .chart-container {
            margin-top: 20px;
            height: 300px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>
            <span>🛡️</span>
            Anti-Bot Monitoring Dashboard
        </h1>
        <a href="?logout" class="logout-btn">Logout</a>
    </div>
    
    <!-- Statistics Cards -->
    <div class="stats-grid">
        <div class="stat-card total">
            <div class="icon">📊</div>
            <div class="label">Total Attempts</div>
            <div class="value"><?= number_format($statistics['total']) ?></div>
        </div>
        
        <div class="stat-card humans">
            <div class="icon">✅</div>
            <div class="label">Humans (Direct Access)</div>
            <div class="value"><?= number_format($statistics['humans']) ?></div>
        </div>
        
        <div class="stat-card uncertain">
            <div class="icon">⚠️</div>
            <div class="label">Uncertain (CAPTCHA)</div>
            <div class="value"><?= number_format($statistics['uncertain']) ?></div>
        </div>
        
        <div class="stat-card bots">
            <div class="icon">🚫</div>
            <div class="label">Bots Blocked</div>
            <div class="value"><?= number_format($statistics['bots']) ?></div>
        </div>
        
        <div class="stat-card">
            <div class="icon">🤖</div>
            <div class="label">Automation Blocked</div>
            <div class="value"><?= number_format($statistics['blocked_automation']) ?></div>
        </div>
        
        <div class="stat-card">
            <div class="icon">📅</div>
            <div class="label">Today</div>
            <div class="value"><?= number_format($statistics['today']) ?></div>
        </div>
        
        <div class="stat-card">
            <div class="icon">⏰</div>
            <div class="label">Last Hour</div>
            <div class="value"><?= number_format($statistics['this_hour']) ?></div>
        </div>
        
        <div class="stat-card">
            <div class="icon">📈</div>
            <div class="label">Detection Rate</div>
            <div class="value">
                <?php 
                $detection_rate = $statistics['total'] > 0 
                    ? round(($statistics['bots'] + $statistics['blocked_automation']) / $statistics['total'] * 100, 1)
                    : 0;
                echo $detection_rate . '%';
                ?>
            </div>
        </div>
    </div>
    
    <!-- Recent Access Attempts -->
    <div class="section">
        <h2>
            <span>📋</span>
            Recent Access Attempts (Last 50)
        </h2>
        
        <?php if (empty($recent_attempts)): ?>
            <div class="empty-state">
                <div class="icon">📭</div>
                <p>No access attempts yet</p>
            </div>
        <?php else: ?>
            <table class="access-table">
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>IP Address</th>
                        <th>Verdict</th>
                        <th>Bot Score</th>
                        <th>User Agent</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($recent_attempts as $index => $attempt): ?>
                        <tr>
                            <td><?= htmlspecialchars($attempt['timestamp'] ?? 'N/A') ?></td>
                            <td><code><?= htmlspecialchars($attempt['ip'] ?? 'N/A') ?></code></td>
                            <td>
                                <?php
                                $verdict = $attempt['verdict'] ?? 'unknown';
                                $verdict_text = [
                                    'human' => 'Human',
                                    'bot' => 'Bot',
                                    'uncertain' => 'Uncertain',
                                    'automation' => 'Automation',
                                    'unknown' => 'Unknown'
                                ];
                                ?>
                                <span class="badge <?= htmlspecialchars($verdict) ?>">
                                    <?= $verdict_text[$verdict] ?? $verdict ?>
                                </span>
                            </td>
                            <td>
                                <span class="score-badge">
                                    <?= isset($attempt['bot_score']) ? round($attempt['bot_score'], 2) . '%' : 'N/A' ?>
                                </span>
                            </td>
                            <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                                <?= htmlspecialchars(substr($attempt['user_agent'] ?? 'N/A', 0, 50)) ?>
                            </td>
                            <td>
                                <button class="details-btn" onclick="showDetails(<?= $index ?>)">
                                    View Details
                                </button>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>
    
    <!-- Details Modal -->
    <div id="detailsModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>Access Attempt Details</h2>
                <button class="close-btn" onclick="closeModal()">Close</button>
            </div>
            <div id="modalBody">
                <!-- Details will be inserted here by JavaScript -->
            </div>
        </div>
    </div>
    
    <button class="refresh-btn" onclick="location.reload()">
        🔄 Refresh
    </button>
    
    <script>
        // Store attempts data for modal
        const attempts = <?= json_encode($recent_attempts) ?>;
        
        function showDetails(index) {
            const attempt = attempts[index];
            const modal = document.getElementById('detailsModal');
            const modalBody = document.getElementById('modalBody');
            
            let html = '';
            
            // Basic Information
            html += '<div class="details-grid">';
            html += `<div class="detail-item">
                <div class="detail-label">IP Address</div>
                <div class="detail-value">${escapeHtml(attempt.ip || 'N/A')}</div>
            </div>`;
            html += `<div class="detail-item">
                <div class="detail-label">Time</div>
                <div class="detail-value">${escapeHtml(attempt.timestamp || 'N/A')}</div>
            </div>`;
            html += `<div class="detail-item">
                <div class="detail-label">Bot Score</div>
                <div class="detail-value">${attempt.bot_score ? attempt.bot_score.toFixed(2) + '%' : 'N/A'}</div>
            </div>`;
            html += `<div class="detail-item">
                <div class="detail-label">Verdict</div>
                <div class="detail-value">${escapeHtml(attempt.verdict || 'N/A')}</div>
            </div>`;
            html += '</div>';
            
            // Bot Characteristics
            if (attempt.characteristics) {
                html += '<h3 style="margin-top: 25px; margin-bottom: 15px; color: #333;">Bot Characteristics Detected:</h3>';
                html += '<div class="details-grid">';
                
                const chars = attempt.characteristics;
                if (chars.sessions) {
                    html += `<div class="detail-item">
                        <div class="detail-label">Number of Sessions</div>
                        <div class="detail-value">${chars.sessions}</div>
                    </div>`;
                }
                if (chars.timing_pattern) {
                    html += `<div class="detail-item">
                        <div class="detail-label">Timing Pattern</div>
                        <div class="detail-value">${escapeHtml(chars.timing_pattern)}</div>
                    </div>`;
                }
                if (chars.error_rate !== undefined) {
                    html += `<div class="detail-item">
                        <div class="detail-label">Error Rate</div>
                        <div class="detail-value">${chars.error_rate}%</div>
                    </div>`;
                }
                if (chars.ui_interaction) {
                    html += `<div class="detail-item">
                        <div class="detail-label">UI Interaction</div>
                        <div class="detail-value">${escapeHtml(chars.ui_interaction)}</div>
                    </div>`;
                }
                if (chars.session_gaps) {
                    html += `<div class="detail-item">
                        <div class="detail-label">Session Gaps</div>
                        <div class="detail-value">${escapeHtml(chars.session_gaps)}</div>
                    </div>`;
                }
                html += '</div>';
            }
            
            // Domain Scores
            if (attempt.domain_scores) {
                html += '<h3 style="margin-top: 25px; margin-bottom: 15px; color: #333;">Detection Domain Analysis:</h3>';
                html += '<div class="domain-scores">';
                
                const domains = attempt.domain_scores;
                if (domains.temporal !== undefined) {
                    html += `<div class="domain-card">
                        <div class="domain-name">⏱️ Temporal Behavior (30%)</div>
                        <div class="domain-score">${domains.temporal}%</div>
                        <div class="domain-contribution">Contribution: ${(domains.temporal * 0.3).toFixed(1)}%</div>
                    </div>`;
                }
                if (domains.interaction !== undefined) {
                    html += `<div class="domain-card">
                        <div class="domain-name">🎯 Interaction Noise (25%)</div>
                        <div class="domain-score">${domains.interaction}%</div>
                        <div class="domain-contribution">Contribution: ${(domains.interaction * 0.25).toFixed(1)}%</div>
                    </div>`;
                }
                if (domains.semantics !== undefined) {
                    html += `<div class="domain-card">
                        <div class="domain-name">🎨 UI Semantics (25%)</div>
                        <div class="domain-score">${domains.semantics}%</div>
                        <div class="domain-contribution">Contribution: ${(domains.semantics * 0.25).toFixed(1)}%</div>
                    </div>`;
                }
                if (domains.continuity !== undefined) {
                    html += `<div class="domain-card">
                        <div class="domain-name">🔄 Session Continuity (20%)</div>
                        <div class="domain-score">${domains.continuity}%</div>
                        <div class="domain-contribution">Contribution: ${(domains.continuity * 0.2).toFixed(1)}%</div>
                    </div>`;
                }
                html += '</div>';
            }
            
            // Detection Flags
            if (attempt.flags && attempt.flags.length > 0) {
                html += '<div class="flags-list">';
                html += '<h3>⚠️ Detection Flags Raised:</h3>';
                html += '<ul>';
                attempt.flags.forEach(flag => {
                    html += `<li>${escapeHtml(flag)}</li>`;
                });
                html += '</ul>';
                html += '</div>';
            }
            
            // User Agent
            html += '<div style="margin-top: 25px; background: #f9fafb; padding: 15px; border-radius: 8px;">';
            html += '<div style="color: #666; font-size: 13px; margin-bottom: 5px;">User Agent:</div>';
            html += `<div style="color: #333; font-size: 14px; word-break: break-all;">${escapeHtml(attempt.user_agent || 'N/A')}</div>`;
            html += '</div>';
            
            // Automation Flags
            if (attempt.automation_flags && attempt.automation_flags.length > 0) {
                html += '<div style="margin-top: 20px; background: #fee2e2; padding: 15px; border-radius: 8px; border-left: 4px solid #ef4444;">';
                html += '<h3 style="color: #991b1b; font-size: 16px; margin-bottom: 10px;">🤖 Automation Tools Blocked:</h3>';
                html += '<ul style="list-style: none; padding: 0;">';
                attempt.automation_flags.forEach(flag => {
                    html += `<li style="padding: 5px 0; color: #7f1d1d;">🚫 ${escapeHtml(flag)}</li>`;
                });
                html += '</ul>';
                html += '</div>';
            }
            
            modalBody.innerHTML = html;
            modal.style.display = 'block';
        }
        
        function closeModal() {
            document.getElementById('detailsModal').style.display = 'none';
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        // Close modal on outside click
        window.onclick = function(event) {
            const modal = document.getElementById('detailsModal');
            if (event.target === modal) {
                closeModal();
            }
        };
        
        // Auto-refresh every 30 seconds
        setTimeout(() => {
            location.reload();
        }, 30000);
    </script>
</body>
</html>
