// static/js/threatIntelligence.worker.js
self.addEventListener('message', async (e) => {
  if (e.data.action === 'CHECK_THREAT_INTELLIGENCE') {
    try {
      await performBatchThreatCheck(e.data.batchSize || 50);
    } catch (error) {
      self.postMessage({
        type: 'ERROR',
        error: error.message
      });
    }
  }
});

async function performBatchThreatCheck(batchSize) {
  try {
    console.log('[Worker] Starting threat intelligence check');
    
    const allIPs = await getAllIPsToCheck();
    const total = allIPs.length;
    
    console.log(`[Worker] Found ${total} IPs to check`);
    
    if (total === 0) {
      self.postMessage({
        type: 'ERROR',
        error: 'No IPs found to analyze'
      });
      return;
    }
    
    const results = [];
    let threatsFound = 0;
    
    for (let i = 0; i < allIPs.length; i += batchSize) {
      const batch = allIPs.slice(i, i + batchSize);
      
      console.log(`[Worker] Processing batch ${Math.floor(i/batchSize) + 1}`);
      
      const batchPromises = batch.map(ip => checkSingleIP(ip));
      const batchResults = await Promise.allSettled(batchPromises);
      
      batchResults.forEach((result, index) => {
        if (result.status === 'fulfilled') {
          results.push(result.value);
          if (result.value.isThreat) threatsFound++;
        } else {
          results.push({
            ip: batch[index],
            error: result.reason?.message || 'Unknown error',
            isThreat: false
          });
        }
      });
      
      const processed = Math.min(i + batchSize, total);
      const progress = Math.round((processed / total) * 100);
      
      self.postMessage({
        type: 'PROGRESS',
        progress: progress,
        processed: processed,
        total: total,
        threatsFound: threatsFound
      });
      
      // Small delay to prevent overwhelming the server
      if (i + batchSize < allIPs.length) {
        await new Promise(resolve => setTimeout(resolve, 300));
      }
    }
    
    console.log(`[Worker] Completed: ${threatsFound} threats found`);
    
    self.postMessage({
      type: 'COMPLETE',
      data: results,
      summary: {
        totalProcessed: results.length,
        threatsFound: threatsFound,
        successRate: Math.round((results.filter(r => !r.error).length / results.length) * 100)
      }
    });
    
  } catch (error) {
    console.error('[Worker] Error:', error);
    self.postMessage({
      type: 'ERROR',
      error: error.message
    });
  }
}

async function getAllIPsToCheck() {
  try {
    console.log('[Worker] Fetching IPs from API');
    const response = await fetch('/api/threat-intelligence/ips?limit=0');
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    const data = await response.json();
    console.log(`[Worker] Received ${data.ips?.length || 0} IPs from API`);
    return data.ips || [];
  } catch (error) {
    console.error('[Worker] Error loading IPs:', error);
    throw new Error(`Failed to load IPs: ${error.message}`);
  }
}

async function checkSingleIP(ip) {
  const controller = new AbortController();
  const timeout = setTimeout(() => {
    controller.abort();
  }, 15000); // 15 second timeout

  try {
    console.log(`[Worker] Checking IP: ${ip}`);
    const response = await fetch(`/api/threat-intelligence/check/${ip}`, {
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/json',
      }
    });

    clearTimeout(timeout);

    if (!response.ok) {
      throw new Error(`API returned ${response.status}`);
    }

    const result = await response.json();
    
    return {
      ip: ip,
      isThreat: result.isThreat || false,
      threatLevel: result.threatLevel || 'low',
      details: result.details || {},
      timestamp: new Date().toISOString()
    };
    
  } catch (error) {
    console.log(`[Worker] Error checking IP ${ip}:`, error.message);
    return {
      ip: ip,
      error: error.message,
      isThreat: false,
      timestamp: new Date().toISOString()
    };
  }
}