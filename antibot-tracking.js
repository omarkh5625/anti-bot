/**
 * Anti-Bot Behavioral Tracking Script
 * This script tracks user behavior to distinguish bots from humans
 * 
 * Detection Domains:
 * 1. Temporal Behavior - Track interaction timing patterns
 * 2. Interaction Noise - Monitor errors, hesitations, cancellations
 * 3. UI Semantics - Observe interaction with visual elements
 * 4. Session Continuity - Track navigation patterns
 */

(function() {
    'use strict';
    
    // Initialize session ID
    const sessionId = sessionStorage.getItem('antibot_session_id') || 
                     'sess_' + Date.now() + '_' + Math.random().toString(36).substring(2, 11);
    sessionStorage.setItem('antibot_session_id', sessionId);
    
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
            
            // Send to server periodically (every 10 actions or 30 seconds)
            if (this.actions.length >= 10 || (now - this.lastSendTime) > 30000) {
                this.sendToServer();
            }
        },
        
        // Send collected data to server
        sendToServer: function() {
            if (this.actions.length === 0) return;
            
            this.lastSendTime = Date.now(); // Update send time
            
            const data = {
                session_id: sessionId,
                action: 'batch_tracking',
                timestamp: Date.now(),
                session_duration: Date.now() - this.sessionStart,
                actions_count: this.actions.length,
                mouse_movements: this.mouseMovements.length,
                clicks_count: this.clicks.length,
                keystrokes_count: this.keystrokes.length,
                errors_count: this.errors.length,
                actions: this.actions.slice(-10), // Send last 10 actions
            };
            
            // Use sendBeacon for reliability
            const formData = new FormData();
            formData.append('track_behavior', '1');
            formData.append('behavior_data', JSON.stringify(data));
            
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
            this.actions = this.actions.slice(-5);
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
    
    // Track mouse movement patterns (sample every 100ms)
    let lastMouseTrack = 0;
    document.addEventListener('mousemove', function(e) {
        const now = Date.now();
        if (now - lastMouseTrack < 100) return; // Throttle to every 100ms
        
        lastMouseTrack = now;
        behaviorTracker.mouseMovements.push({
            x: e.clientX,
            y: e.clientY,
            time: now
        });
        
        // Keep only last 100 movements
        if (behaviorTracker.mouseMovements.length > 100) {
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
    
    // Periodic send (every 30 seconds)
    setInterval(function() {
        if (behaviorTracker.actions.length > 0) {
            behaviorTracker.sendToServer();
        }
    }, 30000);
    
    // Note: Debug mode is disabled in production for security
    // Exposing tracker object could allow manipulation of behavioral data
    // For debugging during development only, uncomment the following:
    // if (window.location.search.includes('debug=antibot')) {
    //     window.antibotTracker = behaviorTracker;
    //     console.log('Anti-bot tracker initialized in debug mode');
    // }
    
})();
