<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Security Check</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    body {
      margin: 0;
      padding: 0;
      height: 100vh;
      display: flex;
      justify-content: center;
      align-items: center;
      background: #f8f9fa;
      font-family: "Segoe UI", Tahoma, Arial, sans-serif;
    }
    .analysis-container {
      text-align: center;
      padding: 40px;
    }
    .spinner {
      width: 50px;
      height: 50px;
      margin: 0 auto 20px;
      border: 4px solid #e0e0e0;
      border-top: 4px solid #007bff;
      border-radius: 50%;
      animation: spin 1s linear infinite;
    }
    @keyframes spin {
      0% { transform: rotate(0deg); }
      100% { transform: rotate(360deg); }
    }
    .message {
      font-size: 18px;
      color: #333;
      margin-bottom: 10px;
    }
    .submessage {
      font-size: 14px;
      color: #666;
    }
  </style>
</head>
<body>
  <div class="analysis-container">
    <div class="spinner"></div>
    <div class="message">Checking your connection security...</div>
    <div class="submessage">This will only take a moment</div>
  </div>
  <!-- Include behavioral tracking script -->
  <script src="antibot-tracking.js"></script>
  <script>
    // Get return URL from query parameter
    const urlParams = new URLSearchParams(window.location.search);
    const returnUrl = urlParams.get('return') || '/';
    
    // Function to check if enough behavioral data has been collected
    function checkBehavioralData() {
      // Check if tracker has collected sufficient actions
      if (window.behaviorTracker) {
        const sessionData = window.behaviorTracker.getSessionData ? window.behaviorTracker.getSessionData() : null;
        if (sessionData && sessionData.actions && sessionData.actions.length >= 3) {
          return true; // Sufficient data
        }
      }
      return false;
    }
    
    // Wait for behavioral data collection with dynamic timing
    let attempts = 0;
    const maxAttempts = 10; // Maximum 5 seconds (10 * 500ms)
    
    const checkInterval = setInterval(async function() {
      attempts++;
      
      // Check if we have enough data OR reached timeout
      if (checkBehavioralData() || attempts >= maxAttempts) {
        clearInterval(checkInterval);
        
        // Send data
        if (window.behaviorTracker && typeof window.behaviorTracker.sendToServer === 'function') {
          window.behaviorTracker.sendToServer();
          // Wait for sendBeacon to complete
          await new Promise(resolve => setTimeout(resolve, 300));
        }
        
        // Verify cookie was set
        let cookieSet = document.cookie.indexOf('analysis_done=yes') !== -1;
        
        // If cookie not set, try setting it via JavaScript as fallback
        if (!cookieSet) {
          document.cookie = 'analysis_done=yes; path=/; max-age=86400';
          // Verify it was set
          cookieSet = document.cookie.indexOf('analysis_done=yes') !== -1;
        }
        
        // Only proceed if cookie is confirmed set
        if (cookieSet) {
          // Return to the original URL
          window.location.href = returnUrl;
        } else {
          // Cookies blocked - show error message
          document.querySelector('.message').textContent = 'Please enable cookies to continue';
          document.querySelector('.submessage').textContent = 'Cookies are required for security verification';
          document.querySelector('.spinner').style.display = 'none';
        }
      }
    }, 500); // Check every 500ms
  </script>
</body>
</html>
