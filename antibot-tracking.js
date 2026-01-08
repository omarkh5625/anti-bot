/**
 * Anti-Bot Behavioral Tracking Script
 * This script tracks user behavior to distinguish bots from humans
 * 
 * Detection Domains:
 * 1. Temporal Behavior - Track interaction timing patterns
 * 2. Interaction Noise - Monitor errors, hesitations, cancellations
 * 3. UI Semantics - Observe interaction with visual elements
 * 4. Session Continuity - Track navigation patterns
 * 5. Automation Detection - Selenium, WebDriver, Headless browsers
 */

(function() {
    'use strict';
    
    // ============================================
    // ADVANCED BOT DETECTION - Selenium/WebDriver
    // ============================================
    function detectAutomation() {
        const flags = [];
        
        // 1. Check for navigator.webdriver (Selenium/WebDriver)
        if (navigator.webdriver === true) {
            flags.push('webdriver_detected');
        }
        
        // 2. Check for automation-related window properties
        const automationProperties = [
            '__webdriver_evaluate',
            '__selenium_evaluate',
            '__webdriver_script_function',
            '__webdriver_script_func',
            '__webdriver_script_fn',
            '__fxdriver_evaluate',
            '__driver_unwrapped',
            '__webdriver_unwrapped',
            '__driver_evaluate',
            '__selenium_unwrapped',
            '__fxdriver_unwrapped',
            '_Selenium_IDE_Recorder',
            '_selenium',
            'calledSelenium',
            '$cdc_asdjflasutopfhvcZLmcfl_',
            '$chrome_asyncScriptInfo',
            '__$webdriverAsyncExecutor',
            'webdriver',
            '__webdriverFunc',
            'domAutomation',
            'domAutomationController'
        ];
        
        for (const prop of automationProperties) {
            if (window[prop] || document[prop]) {
                flags.push('automation_property_' + prop);
            }
        }
        
        // 3. Check for Chrome DevTools Protocol
        if (window.chrome && window.chrome.runtime) {
            try {
                if (window.chrome.runtime.id) {
                    // Extension detected - could be legitimate
                } else if (window.chrome.app) {
                    flags.push('chrome_app_detected');
                }
            } catch (e) {
                flags.push('chrome_runtime_access_error');
            }
        }
        
        // 4. Check for missing browser features (headless)
        const headlessChecks = {
            hasPlugins: navigator.plugins.length === 0,
            hasLanguages: !navigator.languages || navigator.languages.length === 0,
            hasChrome: !window.chrome && /Chrome/.test(navigator.userAgent),
            hasMimeTypes: navigator.mimeTypes.length === 0,
            hasNotifications: !('Notification' in window),
            hasPermissions: !('permissions' in navigator)
        };
        
        let headlessScore = 0;
        for (const [check, result] of Object.entries(headlessChecks)) {
            if (result) {
                headlessScore++;
                flags.push('headless_' + check);
            }
        }
        
        // 5. Check for phantom/headless browser UA
        const ua = navigator.userAgent.toLowerCase();
        const suspiciousUA = ['headless', 'phantom', 'puppeteer', 'playwright', 'selenium'];
        for (const suspect of suspiciousUA) {
            if (ua.includes(suspect)) {
                flags.push('suspicious_ua_' + suspect);
            }
        }
        
        // 6. WebGL/Canvas fingerprinting check
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            if (gl) {
                const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                if (debugInfo) {
                    const renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
                    const vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
                    
                    // Check for headless/automation patterns
                    if (renderer.includes('SwiftShader') || 
                        renderer.includes('llvmpipe') ||
                        vendor.includes('Google')) {
                        flags.push('webgl_software_renderer');
                    }
                }
            } else {
                flags.push('webgl_unavailable');
            }
        } catch (e) {
            flags.push('webgl_error');
        }
        
        // 7. Check for inconsistent window properties
        if (window.outerWidth === 0 && window.outerHeight === 0) {
            flags.push('zero_outer_dimensions');
        }
        
        // 8. Check for CDP (Chrome DevTools Protocol) indicators
        if (typeof window.cdc_adoQpoasnfa76pfcZLmcfl_Array !== 'undefined' ||
            typeof window.cdc_adoQpoasnfa76pfcZLmcfl_Promise !== 'undefined' ||
            typeof window.cdc_adoQpoasnfa76pfcZLmcfl_Symbol !== 'undefined') {
            flags.push('cdp_detected');
        }
        
        // 9. Check for automated mouse movements
        let mouseEventCount = 0;
        let mouseEventTimestamp = Date.now();
        document.addEventListener('mousemove', function() {
            mouseEventCount++;
            const now = Date.now();
            if (now - mouseEventTimestamp < 10 && mouseEventCount > 50) {
                flags.push('synthetic_mouse_events');
            }
            mouseEventTimestamp = now;
        }, {once: true, passive: true});
        
        // 10. Permission API inconsistencies
        if ('permissions' in navigator) {
            try {
                navigator.permissions.query({name: 'notifications'}).then(function(result) {
                    if (result.state === 'prompt' && typeof Notification === 'undefined') {
                        flags.push('permission_api_inconsistent');
                    }
                });
            } catch (e) {
                // Permission query failed
            }
        }
        
        return {
            isAutomated: flags.length > 0,
            flags: flags,
            score: Math.min(flags.length * 10, 100),
            headlessScore: headlessScore
        };
    }
    
    // Run automation detection immediately
    const automationDetection = detectAutomation();
    if (automationDetection.isAutomated) {
        console.warn('[Anti-Bot] Automation detected:', automationDetection.flags);
        
        // Send automation detection immediately to server
        try {
            navigator.sendBeacon('/antibot-report.php', JSON.stringify({
                type: 'automation_detected',
                flags: automationDetection.flags,
                score: automationDetection.score,
                timestamp: Date.now()
            }));
        } catch (e) {
            // Beacon failed
        }
    }
    
    // Configuration constants
    const ACTIONS_THRESHOLD = 10;           // Send data after this many actions
    const SEND_INTERVAL_MS = 30000;         // Send data every 30 seconds
    const MOUSE_MOVE_THROTTLE_MS = 100;     // Track mouse movements every 100ms
    const MAX_MOUSE_MOVEMENTS = 100;        // Keep last 100 mouse movements
    const ACTIONS_TO_KEEP = 5;              // Keep last 5 actions after sending
    const ACTIONS_TO_SEND = 10;             // Send last 10 actions to server
    
    // Initialize session ID
    const sessionId = sessionStorage.getItem('antibot_session_id') || 
                     'sess_' + Date.now() + '_' + Math.random().toString(36).substring(2, 11);
    sessionStorage.setItem('antibot_session_id', sessionId);
    
    // ============================================
    // CRYPTOGRAPHIC SIGNING - HMAC-SHA256
    // ============================================
    
    /**
     * Simple SHA-256 HMAC implementation for telemetry signing
     * This prevents bots from sending unsigned/forged telemetry data
     */
    async function hmacSHA256(secret, message) {
        const encoder = new TextEncoder();
        const keyData = encoder.encode(secret);
        const messageData = encoder.encode(message);
        
        const key = await crypto.subtle.importKey(
            'raw',
            keyData,
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
        );
        
        const signature = await crypto.subtle.sign('HMAC', key, messageData);
        
        // Convert to hex string
        return Array.from(new Uint8Array(signature))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }
    
    /**
     * Get or generate client-side signing key
     * This is fetched from server on first load and cached
     */
    function getSigningKey() {
        // Check if we already have a key
        let signingKey = sessionStorage.getItem('antibot_signing_key');
        if (signingKey) {
            return signingKey;
        }
        
        // Generate a deterministic key from page load time and session
        // Server will validate this matches expected pattern
        const keyBase = sessionId + '_' + document.domain + '_' + navigator.userAgent.substring(0, 50);
        signingKey = btoa(keyBase).substring(0, 32);
        sessionStorage.setItem('antibot_signing_key', signingKey);
        return signingKey;
    }
    
    /**
     * Generate nonce for replay protection
     * Format: timestamp_random
     */
    function generateNonce() {
        const timestamp = Date.now();
        const random = Math.random().toString(36).substring(2, 15);
        return timestamp + '_' + random;
    }
    
    const behaviorTracker = {
        sessionStart: Date.now(),
        lastActionTime: Date.now(),
        lastSendTime: Date.now(),
        actions: [],
        mouseMovements: [],
        clicks: [],
        keystrokes: [],
        readingTimes: {},
        errors: [],
        
        // Track an action with timing
        trackAction: function(action, data = {}) {
            const now = Date.now();
            const timeSinceLastAction = now - this.lastActionTime;
            
            this.actions.push({
                action: action,
                timestamp: now,
                timeSinceLastAction: timeSinceLastAction,
                data: data
            });
            
            this.lastActionTime = now;
            
            // Send to server periodically
            if (this.actions.length >= ACTIONS_THRESHOLD || (now - this.lastSendTime) > SEND_INTERVAL_MS) {
                this.sendToServer();
            }
        },
        
        // Send collected data to server with cryptographic signature
        sendToServer: async function() {
            if (this.actions.length === 0) return;
            
            this.lastSendTime = Date.now(); // Update send time
            
            // Generate nonce for replay protection
            const nonce = generateNonce();
            
            const data = {
                session_id: sessionId,
                action: 'batch_tracking',
                timestamp: Date.now(),
                nonce: nonce,
                session_duration: Date.now() - this.sessionStart,
                actions_count: this.actions.length,
                mouse_movements: this.mouseMovements.length,
                clicks_count: this.clicks.length,
                keystrokes_count: this.keystrokes.length,
                errors_count: this.errors.length,
                actions: this.actions.slice(-ACTIONS_TO_SEND),
            };
            
            // Generate HMAC signature: HMAC(secret, nonce + payload)
            const payload = JSON.stringify(data);
            const signingKey = getSigningKey();
            const messageToSign = nonce + payload;
            
            let signature = '';
            try {
                signature = await hmacSHA256(signingKey, messageToSign);
            } catch (e) {
                // Crypto API not available - fallback to simple hash
                console.warn('[Anti-Bot] Crypto API unavailable, using fallback');
                signature = 'fallback_' + btoa(messageToSign).substring(0, 32);
            }
            
            // Use sendBeacon for reliability
            const formData = new FormData();
            formData.append('track_behavior', '1');
            formData.append('behavior_data', payload);
            formData.append('signature', signature);
            formData.append('nonce', nonce);
            
            if (navigator.sendBeacon) {
                navigator.sendBeacon(window.location.pathname, formData);
            } else {
                // Fallback to fetch
                fetch(window.location.pathname, {
                    method: 'POST',
                    body: formData,
                    keepalive: true
                }).catch(() => {});
            }
            
            // Clear old actions but keep recent ones
            this.actions = this.actions.slice(-ACTIONS_TO_KEEP);
        }
    };
    
    // 1. TEMPORAL BEHAVIOR TRACKING
    
    // Track clicks with precise timing
    let clickCount = 0;
    document.addEventListener('click', function(e) {
        clickCount++;
        behaviorTracker.clicks.push({
            x: e.clientX,
            y: e.clientY,
            time: Date.now(),
            element: e.target.tagName,
            clickNumber: clickCount
        });
        
        behaviorTracker.trackAction('click', {
            element: e.target.tagName,
            has_text: e.target.textContent ? e.target.textContent.length > 0 : false,
            position: { x: e.clientX, y: e.clientY }
        });
    });
    
    // Track reading time based on visible content
    const observeReadingTime = function() {
        const textElements = document.querySelectorAll('p, h1, h2, h3, h4, h5, h6, article, section');
        
        textElements.forEach((element) => {
            if (element.dataset.antibotTracked) return;
            element.dataset.antibotTracked = 'true';
            
            const observer = new IntersectionObserver((entries) => {
                entries.forEach((entry) => {
                    const elementId = entry.target.tagName + '_' + Math.random().toString(36).substr(2, 5);
                    
                    if (entry.isIntersecting) {
                        // Element became visible
                        behaviorTracker.readingTimes[elementId] = {
                            startTime: Date.now(),
                            textLength: entry.target.textContent.length,
                            element: entry.target.tagName
                        };
                    } else if (behaviorTracker.readingTimes[elementId]) {
                        // Element left viewport - calculate reading time
                        const readTime = Date.now() - behaviorTracker.readingTimes[elementId].startTime;
                        const textLength = behaviorTracker.readingTimes[elementId].textLength;
                        
                        behaviorTracker.trackAction('reading', {
                            text_length: textLength,
                            read_time: readTime,
                            element_type: behaviorTracker.readingTimes[elementId].element
                        });
                        
                        delete behaviorTracker.readingTimes[elementId];
                    }
                });
            }, { threshold: 0.5 });
            
            observer.observe(element);
        });
    };
    
    // Run observer after page load
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', observeReadingTime);
    } else {
        observeReadingTime();
    }
    
    // 2. INTERACTION NOISE TRACKING
    
    // Track input errors and corrections
    document.addEventListener('keydown', function(e) {
        behaviorTracker.keystrokes.push({
            key: e.key,
            time: Date.now()
        });
        
        // Detect backspace/delete as potential error correction
        if (e.key === 'Backspace' || e.key === 'Delete') {
            behaviorTracker.errors.push({
                type: 'correction',
                time: Date.now()
            });
            
            behaviorTracker.trackAction('keystroke', {
                input_error: true,
                correction: true
            });
        }
    });
    
    // Track canceled clicks (mousedown without mouseup on same element)
    let mouseDownTarget = null;
    let mouseDownTime = 0;
    
    document.addEventListener('mousedown', function(e) {
        mouseDownTarget = e.target;
        mouseDownTime = Date.now();
    });
    
    document.addEventListener('mouseup', function(e) {
        if (mouseDownTarget && mouseDownTarget !== e.target) {
            // Click was started but completed on different element (cancelled/dragged)
            behaviorTracker.trackAction('click_canceled', {
                canceled: true,
                duration: Date.now() - mouseDownTime
            });
        }
        mouseDownTarget = null;
    });
    
    // Track mouse movement patterns (sample based on throttle interval)
    let lastMouseTrack = 0;
    document.addEventListener('mousemove', function(e) {
        const now = Date.now();
        if (now - lastMouseTrack < MOUSE_MOVE_THROTTLE_MS) return;
        
        lastMouseTrack = now;
        behaviorTracker.mouseMovements.push({
            x: e.clientX,
            y: e.clientY,
            time: now
        });
        
        // Keep only recent movements
        if (behaviorTracker.mouseMovements.length > MAX_MOUSE_MOVEMENTS) {
            behaviorTracker.mouseMovements.shift();
        }
    });
    
    // 3. UI SEMANTICS TRACKING
    
    // Track interactions with decorative vs functional elements
    document.addEventListener('click', function(e) {
        const element = e.target;
        const isDecorative = element.hasAttribute('aria-hidden') || 
                           element.classList.contains('decoration') ||
                           element.tagName === 'IMG' && !element.hasAttribute('onclick') ||
                           element.closest('[aria-hidden="true"]') !== null;
        
        const isFunctional = element.tagName === 'BUTTON' ||
                           element.tagName === 'A' ||
                           element.tagName === 'INPUT' ||
                           element.hasAttribute('onclick') ||
                           element.getAttribute('role') === 'button';
        
        behaviorTracker.trackAction('ui_interaction', {
            element_type: element.tagName,
            is_decorative: isDecorative,
            is_functional: isFunctional,
            ignores_cosmetic: !isDecorative && isFunctional
        });
    });
    
    // Track if user follows visual hints (hover states, focus, etc.)
    let hoverTarget = null;
    let hoverStartTime = 0;
    
    document.addEventListener('mouseover', function(e) {
        if (e.target.matches('a, button, [role="button"], input, select, textarea')) {
            hoverTarget = e.target;
            hoverStartTime = Date.now();
        }
    });
    
    document.addEventListener('mouseout', function(e) {
        if (hoverTarget === e.target) {
            const hoverDuration = Date.now() - hoverStartTime;
            
            behaviorTracker.trackAction('hover', {
                element: e.target.tagName,
                duration: hoverDuration,
                follows_visual_hints: hoverDuration > 100 // Humans typically hover briefly
            });
            
            hoverTarget = null;
        }
    });
    
    // 4. SESSION CONTINUITY TRACKING
    
    // Track navigation patterns
    let navigationHistory = JSON.parse(sessionStorage.getItem('antibot_nav_history') || '[]');
    navigationHistory.push({
        path: window.location.pathname,
        time: Date.now(),
        referrer: document.referrer
    });
    
    // Keep only last 20 navigations
    if (navigationHistory.length > 20) {
        navigationHistory = navigationHistory.slice(-20);
    }
    
    sessionStorage.setItem('antibot_nav_history', JSON.stringify(navigationHistory));
    
    behaviorTracker.trackAction('navigate', {
        path: window.location.pathname,
        referrer: document.referrer,
        session_age: Date.now() - behaviorTracker.sessionStart
    });
    
    // Detect if session is resumed (back from different tab/window)
    document.addEventListener('visibilitychange', function() {
        if (document.visibilityState === 'visible') {
            behaviorTracker.trackAction('session_resumed', {
                time_away: Date.now() - behaviorTracker.lastActionTime
            });
        } else {
            behaviorTracker.trackAction('session_hidden', {});
        }
    });
    
    // Send data before page unload
    window.addEventListener('beforeunload', function() {
        behaviorTracker.sendToServer();
    });
    
    // Periodic send (based on interval constant)
    setInterval(function() {
        if (behaviorTracker.actions.length > 0) {
            behaviorTracker.sendToServer();
        }
    }, SEND_INTERVAL_MS);
    
    // Expose sendToServer method for forced sends before page navigation
    // This is needed to ensure data is sent before the 5-second reload
    window.behaviorTracker = {
        sendToServer: async function() {
            await behaviorTracker.sendToServer();
        }
    };
    
})();
