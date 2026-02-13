# Member 3 Guide: Frontend Developer (Dashboard + Visualization)

## Role Summary

As the Frontend Developer, you are responsible for:
- **Dashboard:** Building the web-based user interface
- **Visualization:** Creating charts with Chart.js
- **Real-time Updates:** Polling the API every 3 seconds
- **User Experience:** Responsive design, clear data presentation

Your work is what users see and interact with.

---

## Files You Own

| File | Purpose |
|------|---------|
| `frontend/index.html` | Main dashboard page |
| `frontend/devices.html` | Device list page |
| `frontend/alerts.html` | Alert feed page |
| `frontend/css/styles.css` | Custom styling |
| `frontend/js/api.js` | API communication functions |
| `frontend/js/charts.js` | Chart.js configurations |
| `frontend/js/dashboard.js` | Dashboard update logic |

---

## Detailed File Descriptions

### frontend/index.html

**Purpose:** The main dashboard showing network overview.

**What it should contain:**
1. HTML5 document structure
2. Bootstrap 5 CSS (CDN)
3. Chart.js (CDN)
4. Navigation bar with links to all pages
5. Metric cards row (bandwidth, devices, packets/sec, health)
6. Charts row (bandwidth line chart, protocol pie chart)
7. Top devices table
8. Script tags for your JS files

**Layout Structure:**
```
┌─────────────────────────────────────────────────────────┐
│ Navigation Bar: [NetWatch] [Dashboard] [Devices] [Alerts] │
├─────────────────────────────────────────────────────────┤
│ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ │
│ │ Bandwidth │ │  Devices  │ │ Packets/s │ │  Health   │ │
│ │  2.5 MB/s │ │    42     │ │    156    │ │    85     │ │
│ └───────────┘ └───────────┘ └───────────┘ └───────────┘ │
├─────────────────────────────────────────────────────────┤
│ ┌─────────────────────┐ ┌─────────────────────┐         │
│ │  Bandwidth Chart    │ │   Protocol Chart    │         │
│ │   (Line Chart)      │ │   (Pie/Doughnut)    │         │
│ └─────────────────────┘ └─────────────────────┘         │
├─────────────────────────────────────────────────────────┤
│ Top Devices Table                                        │
│ ┌───────────────────────────────────────────────────┐   │
│ │ IP Address    │ Hostname    │ Bandwidth │ Last Seen│  │
│ │ 192.168.1.105 │ Johns-Mac   │ 500 MB   │ 14:30    │  │
│ └───────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────┤
│ Footer: Last updated: 14:30:45                           │
└─────────────────────────────────────────────────────────┘
```

---

### frontend/js/api.js

**Purpose:** Handle all API communication.

**What it should contain:**

```javascript
// Configuration
const API_BASE_URL = 'http://localhost:5000/api';

// Generic fetch wrapper
async function fetchApi(endpoint, options = {}) { }

// Specific API functions
async function getStatus() { }
async function getRealtimeStats() { }
async function getTopDevices(limit = 10) { }
async function getProtocols(hours = 1) { }
async function getBandwidthHistory(hours = 1) { }
async function getAlerts(limit = 50, severity = null) { }
async function getHealthScore() { }
async function updateDeviceName(ipAddress, hostname) { }
```

---

### frontend/js/charts.js

**Purpose:** Create and update Chart.js charts.

**What it should contain:**

```javascript
// Global chart instances
let bandwidthChart = null;
let protocolChart = null;

// Chart creation functions
function createBandwidthChart(canvasId) { }
function createProtocolChart(canvasId) { }

// Chart update functions
function updateBandwidthChart(chart, historyData) { }
function updateProtocolChart(chart, protocolData) { }

// Utility functions
function formatBytes(bytes) { }
function formatTimestamp(timestamp) { }
```

---

### frontend/js/dashboard.js

**Purpose:** Main dashboard initialization and update loop.

**What it should contain:**

```javascript
const REFRESH_INTERVAL = 3000; // 3 seconds

// Initialization
function initDashboard() { }

// Update functions
async function updateMetrics() { }
async function updateHealthScore() { }
async function updateBandwidthHistory() { }
async function updateProtocolDistribution() { }
async function updateTopDevices() { }

// Main refresh loop
async function refreshDashboard() { }

// Event listener
document.addEventListener('DOMContentLoaded', initDashboard);
```

---

## Week-by-Week Schedule

### Week 1: HTML Structure
- [ ] Create basic index.html with Bootstrap layout
- [ ] Add navigation bar
- [ ] Add metric cards (static placeholders)
- [ ] Add chart containers (empty canvas elements)
- [ ] Add devices table structure
- [ ] Create devices.html skeleton
- [ ] Create alerts.html skeleton

### Week 2: API Integration
- [ ] Implement api.js with all fetch functions
- [ ] Test API calls in browser console
- [ ] Handle errors gracefully
- [ ] Add loading states to HTML

### Week 3: Charts
- [ ] Implement charts.js
- [ ] Create bandwidth line chart
- [ ] Create protocol pie chart
- [ ] Test charts with mock data
- [ ] Style charts (colors, fonts)

### Week 4: Dashboard Logic
- [ ] Implement dashboard.js
- [ ] Connect API to metric cards
- [ ] Connect API to charts
- [ ] Connect API to devices table
- [ ] Implement 3-second refresh loop

### Week 5: Devices & Alerts Pages
- [ ] Complete devices.html functionality
- [ ] Add search and sort
- [ ] Complete alerts.html functionality
- [ ] Add severity filtering
- [ ] Implement hostname editing

### Week 6: Polish
- [ ] Custom CSS styling
- [ ] Responsive testing
- [ ] Loading/error states
- [ ] Final testing
- [ ] Demo preparation

---

## Module Connections

### What You Receive (Inputs)

| From | What | How |
|------|------|-----|
| Member 2 | JSON from `/api/stats/realtime` | fetch() call |
| Member 2 | JSON from `/api/devices/top` | fetch() call |
| Member 2 | JSON from `/api/protocols` | fetch() call |
| Member 2 | JSON from `/api/bandwidth/history` | fetch() call |
| Member 2 | JSON from `/api/alerts` | fetch() call |
| Member 2 | JSON from `/api/health` | fetch() call |

### What You Provide (Outputs)

| To | What | Purpose |
|----|------|---------|
| Users | Visual dashboard | Data presentation |
| Member 2 | POST to `/api/devices/update-name` | Hostname updates |

### Data Flow

```
API (Member 2)
    │
    │ JSON Response
    ▼
api.js (fetch functions)
    │
    │ JavaScript objects
    ▼
dashboard.js / charts.js
    │
    │ DOM updates
    ▼
Browser (HTML rendering)
```

---

## CDN Links to Use

Add these to your HTML `<head>`:

```html
<!-- Bootstrap 5 CSS -->
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">

<!-- Your custom CSS -->
<link href="css/styles.css" rel="stylesheet">
```

Add these before `</body>`:

```html
<!-- Bootstrap 5 JS (optional, for interactive components) -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>

<!-- Chart.js -->
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>

<!-- Your JavaScript files -->
<script src="js/api.js"></script>
<script src="js/charts.js"></script>
<script src="js/dashboard.js"></script>
```

---

## Example Code

### Complete api.js

```javascript
const API_BASE_URL = 'http://localhost:5000/api';

async function fetchApi(endpoint, options = {}) {
    try {
        const response = await fetch(API_BASE_URL + endpoint, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            }
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            return { success: false, error: data.error || 'Request failed' };
        }
        
        return { success: true, data };
    } catch (error) {
        console.error('API Error:', error);
        return { success: false, error: error.message };
    }
}

async function getStatus() {
    return fetchApi('/status');
}

async function getRealtimeStats() {
    return fetchApi('/stats/realtime');
}

async function getTopDevices(limit = 10) {
    return fetchApi(`/devices/top?limit=${limit}`);
}

async function getProtocols(hours = 1) {
    return fetchApi(`/protocols?hours=${hours}`);
}

async function getBandwidthHistory(hours = 1) {
    return fetchApi(`/bandwidth/history?hours=${hours}`);
}

async function getAlerts(limit = 50, severity = null) {
    let url = `/alerts?limit=${limit}`;
    if (severity) {
        url += `&severity=${severity}`;
    }
    return fetchApi(url);
}

async function getHealthScore() {
    return fetchApi('/health');
}

async function updateDeviceName(ipAddress, hostname) {
    return fetchApi('/devices/update-name', {
        method: 'POST',
        body: JSON.stringify({ ip_address: ipAddress, hostname })
    });
}
```

### Complete charts.js

```javascript
let bandwidthChart = null;
let protocolChart = null;

function createBandwidthChart(canvasId) {
    const ctx = document.getElementById(canvasId).getContext('2d');
    
    bandwidthChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Bandwidth (MB/s)',
                data: [],
                borderColor: 'rgb(75, 192, 192)',
                backgroundColor: 'rgba(75, 192, 192, 0.1)',
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'MB/s'
                    }
                },
                x: {
                    title: {
                        display: true,
                        text: 'Time'
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                }
            }
        }
    });
    
    return bandwidthChart;
}

function createProtocolChart(canvasId) {
    const ctx = document.getElementById(canvasId).getContext('2d');
    
    protocolChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [
                    'rgb(54, 162, 235)',   // HTTPS - blue
                    'rgb(255, 205, 86)',   // HTTP - yellow
                    'rgb(75, 192, 192)',   // DNS - teal
                    'rgb(255, 99, 132)',   // SSH - red
                    'rgb(153, 102, 255)',  // FTP - purple
                    'rgb(201, 203, 207)'   // Other - gray
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right'
                }
            }
        }
    });
    
    return protocolChart;
}

function updateBandwidthChart(chart, historyData) {
    chart.data.labels = historyData.map(d => formatTimestamp(d.timestamp));
    chart.data.datasets[0].data = historyData.map(d => d.bytes_per_second / 1000000);
    chart.update('none'); // 'none' for no animation on updates
}

function updateProtocolChart(chart, protocolData) {
    chart.data.labels = protocolData.map(p => p.name);
    chart.data.datasets[0].data = protocolData.map(p => p.count);
    chart.update('none');
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatTimestamp(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleTimeString('en-US', { 
        hour: '2-digit', 
        minute: '2-digit',
        hour12: false 
    });
}
```

### Complete dashboard.js

```javascript
const REFRESH_INTERVAL = 3000;
let refreshIntervalId = null;

async function initDashboard() {
    console.log('Initializing dashboard...');
    
    // Create charts
    createBandwidthChart('bandwidthCanvas');
    createProtocolChart('protocolCanvas');
    
    // Initial data load
    await refreshDashboard();
    
    // Start auto-refresh
    refreshIntervalId = setInterval(refreshDashboard, REFRESH_INTERVAL);
    
    console.log('Dashboard initialized');
}

async function refreshDashboard() {
    try {
        await Promise.all([
            updateMetrics(),
            updateHealthScore(),
            updateBandwidthHistory(),
            updateProtocolDistribution(),
            updateTopDevices()
        ]);
        
        document.getElementById('lastUpdated').textContent = 
            new Date().toLocaleTimeString();
    } catch (error) {
        console.error('Dashboard refresh failed:', error);
    }
}

async function updateMetrics() {
    const result = await getRealtimeStats();
    if (result.success) {
        document.getElementById('bandwidthValue').textContent = 
            formatBytes(result.data.bandwidth_bps) + '/s';
        document.getElementById('devicesValue').textContent = 
            result.data.active_devices;
        document.getElementById('packetsValue').textContent = 
            result.data.packets_per_second;
    }
}

async function updateHealthScore() {
    const result = await getHealthScore();
    if (result.success) {
        const score = result.data.score;
        const healthEl = document.getElementById('healthValue');
        healthEl.textContent = score;
        
        // Update color based on score
        healthEl.className = 'card-value';
        if (score >= 80) {
            healthEl.classList.add('text-success');
        } else if (score >= 50) {
            healthEl.classList.add('text-warning');
        } else {
            healthEl.classList.add('text-danger');
        }
    }
}

async function updateBandwidthHistory() {
    const result = await getBandwidthHistory(1);
    if (result.success && bandwidthChart) {
        updateBandwidthChart(bandwidthChart, result.data.history);
    }
}

async function updateProtocolDistribution() {
    const result = await getProtocols(1);
    if (result.success && protocolChart) {
        updateProtocolChart(protocolChart, result.data.protocols);
    }
}

async function updateTopDevices() {
    const result = await getTopDevices(10);
    if (result.success) {
        const tbody = document.getElementById('devicesTableBody');
        tbody.innerHTML = result.data.devices.map(device => `
            <tr>
                <td>${device.ip_address}</td>
                <td>${device.hostname || '<em>Unknown</em>'}</td>
                <td>${formatBytes(device.total_bytes)}</td>
                <td>${formatTimestamp(device.last_seen)}</td>
            </tr>
        `).join('');
    }
}

// Pause refresh when tab is hidden
document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
        clearInterval(refreshIntervalId);
    } else {
        refreshDashboard();
        refreshIntervalId = setInterval(refreshDashboard, REFRESH_INTERVAL);
    }
});

document.addEventListener('DOMContentLoaded', initDashboard);
```

---

## Common Mistakes to Avoid

1. **CORS errors**
   - Make sure backend has CORS enabled
   - Check that API_BASE_URL is correct

2. **Chart not rendering**
   - Canvas element must exist before creating chart
   - Check canvas ID matches JavaScript

3. **Data not updating**
   - Check browser console for errors
   - Verify API responses in Network tab

4. **Memory leaks**
   - Don't create new charts on every refresh
   - Update existing chart data instead

5. **Blocking UI with sync code**
   - Always use async/await
   - Handle errors in try/catch

6. **Not handling empty data**
   ```javascript
   // Always check before using
   if (result.data && result.data.devices) {
       // safe to use
   }
   ```

---

## Using AI Effectively

### Good Prompts for Your Tasks

**For HTML structure:**
```
"Write an HTML5 page for a network monitoring dashboard with:
1. Bootstrap 5 navbar with links: Dashboard, Devices, Alerts
2. Row of 4 Bootstrap cards showing: Bandwidth, Active Devices, Packets/sec, Health Score
3. Row with two chart containers (canvas elements)
4. A table for top devices with columns: IP, Hostname, Bandwidth, Last Seen
5. Include CDN links for Bootstrap 5 and Chart.js
6. Include script tags for api.js, charts.js, dashboard.js at the bottom"
```

**For Chart.js:**
```
"Write JavaScript to create a Chart.js line chart that:
1. Shows bandwidth over time
2. X-axis is time (HH:MM format)
3. Y-axis is MB/s
4. Has a smooth curved line with gradient fill
5. Is responsive
6. Has an update function that takes new data array
Include the function to format bytes to MB"
```

**For fetch logic:**
```
"Write a JavaScript async function that:
1. Fetches from /api/stats/realtime
2. Parses JSON response
3. Updates DOM elements with IDs: bandwidthValue, devicesValue, packetsValue
4. Handles errors gracefully (logs to console, doesn't crash)
5. Formats bandwidth bytes as 'X.XX MB/s'"
```

---

## Testing Your Frontend

### Using Browser DevTools

1. **Console Tab:** Check for JavaScript errors
2. **Network Tab:** See API requests and responses
3. **Elements Tab:** Inspect DOM updates
4. **Responsive Mode:** Test mobile layouts

### Test Without Backend

You can test with mock data:

```javascript
// Temporary mock for testing
async function getRealtimeStats() {
    return {
        success: true,
        data: {
            bandwidth_bps: 2500000,
            active_devices: 42,
            packets_per_second: 156
        }
    };
}
```

### Test Checklist

- [ ] Dashboard loads without console errors
- [ ] All metric cards display data
- [ ] Bandwidth chart shows line graph
- [ ] Protocol chart shows pie chart
- [ ] Devices table populates
- [ ] Data updates every 3 seconds
- [ ] Responsive on mobile
- [ ] Devices page shows full list
- [ ] Alerts page shows alerts with colors

---

## Coordination with Team

### With Member 2 (Backend)
- **Get API response formats** early
- **Test your fetch calls** against their endpoints
- **Report any issues** with API responses

### With Member 1 (Project Lead)
- **Get configuration values** (API port, refresh interval)
- **Report visual bugs** that might indicate backend issues
