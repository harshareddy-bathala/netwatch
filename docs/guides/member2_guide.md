# Member 2 Guide: Backend Developer (Flask REST API)

## Role Summary

As the Backend Developer, you are responsible for:
- **Flask Application:** Creating and configuring the Flask server
- **REST API:** Defining all API endpoints
- **Data Transformation:** Converting database results to JSON responses
- **Error Handling:** Proper HTTP status codes and error messages

Your API is the bridge between the database and the frontend dashboard.

---

## Files You Own

| File | Purpose |
|------|---------|
| `backend/__init__.py` | Package initialization |
| `backend/app.py` | Flask application factory |
| `backend/routes.py` | All API endpoint definitions |

---

## Detailed File Descriptions

### backend/app.py

**Purpose:** Create and configure the Flask application.

**What it should do:**
1. Create Flask app instance
2. Configure CORS for cross-origin requests
3. Set up static file serving for frontend
4. Register all routes
5. Configure error handlers (404, 500)

**Functions to implement:**

```python
def create_app():
    """
    Application factory - creates and configures Flask app.
    
    Returns:
        Flask: Configured Flask application instance
    """
    pass

def handle_404(error):
    """Handle 404 Not Found errors."""
    pass

def handle_500(error):
    """Handle 500 Internal Server errors."""
    pass
```

**Key imports:**
```python
from flask import Flask, jsonify
from flask_cors import CORS
from backend.routes import register_routes
```

---

### backend/routes.py

**Purpose:** Define all REST API endpoints.

**Endpoints to implement:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/status` | System status |
| GET | `/api/stats/realtime` | Current statistics |
| GET | `/api/devices/top` | Top devices by bandwidth |
| GET | `/api/protocols` | Protocol distribution |
| GET | `/api/bandwidth/history` | Bandwidth over time |
| GET | `/api/alerts` | System alerts |
| GET | `/api/health` | Health score |
| POST | `/api/devices/update-name` | Update device hostname |

**Function to implement:**

```python
def register_routes(app):
    """
    Register all API routes with the Flask app.
    
    Args:
        app: Flask application instance
    """
    pass
```

---

## Week-by-Week Schedule

### Week 1: Setup & Structure
- [ ] Create `app.py` with basic Flask setup
- [ ] Add CORS configuration
- [ ] Create `routes.py` with register_routes function
- [ ] Implement `/api/status` endpoint (no database needed)
- [ ] Test that Flask starts and returns JSON

### Week 2: Core Endpoints
- [ ] Implement `/api/stats/realtime`
- [ ] Implement `/api/devices/top`
- [ ] Implement `/api/protocols`
- [ ] Test each endpoint with curl
- [ ] Handle query parameters

### Week 3: History & Alerts
- [ ] Implement `/api/bandwidth/history`
- [ ] Implement `/api/alerts`
- [ ] Implement `/api/health`
- [ ] Add query parameter validation
- [ ] Test with different parameter values

### Week 4: Write Operations
- [ ] Implement `POST /api/devices/update-name`
- [ ] Add request body validation
- [ ] Add error handling for all endpoints
- [ ] Implement 404 and 500 handlers

### Week 5: Integration & Testing
- [ ] Test all endpoints with frontend
- [ ] Fix any integration issues
- [ ] Add response formatting consistency
- [ ] Performance testing

### Week 6: Polish
- [ ] Final testing
- [ ] Update API documentation
- [ ] Code cleanup
- [ ] Demo preparation

---

## Module Connections

### What You Receive (Inputs)

| From | What | Used In |
|------|------|---------|
| Member 5 | `get_realtime_stats()` | /api/stats/realtime |
| Member 5 | `get_top_devices()` | /api/devices/top |
| Member 5 | `get_protocol_distribution()` | /api/protocols |
| Member 5 | `get_bandwidth_history()` | /api/bandwidth/history |
| Member 5 | `get_alerts()` | /api/alerts |
| Member 5 | `get_health_score()` | /api/health |
| Member 5 | `update_device_name()` | /api/devices/update-name |
| Member 1 | `config.py` values | FLASK_HOST, FLASK_PORT |

### What You Provide (Outputs)

| To | What | Purpose |
|----|------|---------|
| Member 3 | JSON API responses | Data for dashboard |
| Member 1 | `create_app()` function | For main.py to start server |

### Data Flow

```
Frontend (Member 3)
    │
    │ HTTP Request (fetch)
    ▼
routes.py (Your Code)
    │
    │ Function call
    ▼
db_handler.py (Member 5)
    │
    │ SQL Query
    ▼
netwatch.db
    │
    │ Query results
    ▼
db_handler.py
    │
    │ Python dict/list
    ▼
routes.py
    │
    │ jsonify()
    ▼
Frontend
```

---

## API Endpoint Specifications

### GET /api/status

**Purpose:** Check if the system is running.

**Request:** No parameters

**Response:**
```json
{
    "status": "running",
    "uptime": 3600,
    "version": "1.0.0"
}
```

**Implementation:**
```python
@app.route('/api/status')
def get_status():
    return jsonify({
        'status': 'running',
        'version': '1.0.0',
        'uptime': get_uptime_seconds()  # You'll need to track this
    })
```

---

### GET /api/stats/realtime

**Purpose:** Get current network statistics.

**Request:** No parameters

**Response:**
```json
{
    "bandwidth_bps": 1234567,
    "active_devices": 42,
    "packets_per_second": 156
}
```

**Implementation:**
```python
@app.route('/api/stats/realtime')
def get_realtime():
    stats = get_realtime_stats()  # From db_handler
    return jsonify(stats)
```

---

### GET /api/devices/top

**Purpose:** Get devices using most bandwidth.

**Query Parameters:**
- `limit` (optional, default 10): Number of devices
- `hours` (optional, default 1): Time window

**Response:**
```json
{
    "devices": [
        {
            "ip_address": "192.168.1.105",
            "hostname": "Johns-MacBook",
            "total_bytes": 524288000,
            "last_seen": "2026-02-01T14:30:00Z"
        }
    ]
}
```

**Implementation:**
```python
@app.route('/api/devices/top')
def get_top_devices_route():
    limit = request.args.get('limit', 10, type=int)
    hours = request.args.get('hours', 1, type=int)
    devices = get_top_devices(limit=limit, hours=hours)
    return jsonify({'devices': devices})
```

---

### GET /api/protocols

**Purpose:** Get protocol distribution.

**Query Parameters:**
- `hours` (optional, default 1): Time window

**Response:**
```json
{
    "protocols": [
        {"name": "HTTPS", "count": 15000, "bytes": 52428800, "percentage": 45.5}
    ]
}
```

---

### GET /api/bandwidth/history

**Purpose:** Get bandwidth over time for charting.

**Query Parameters:**
- `hours` (optional, default 1): Time window (1, 6, 12, 24)

**Response:**
```json
{
    "history": [
        {"timestamp": "2026-02-01T14:00:00Z", "bytes_per_second": 1234567}
    ]
}
```

---

### GET /api/alerts

**Purpose:** Get system alerts.

**Query Parameters:**
- `limit` (optional, default 50): Max alerts
- `severity` (optional): Filter by severity

**Response:**
```json
{
    "alerts": [
        {
            "id": 42,
            "timestamp": "2026-02-01T14:25:00Z",
            "alert_type": "bandwidth",
            "severity": "warning",
            "message": "High bandwidth usage detected",
            "resolved": false
        }
    ]
}
```

---

### GET /api/health

**Purpose:** Get network health score.

**Response:**
```json
{
    "score": 85,
    "status": "good",
    "factors": {}
}
```

---

### POST /api/devices/update-name

**Purpose:** Update a device's hostname.

**Request Body:**
```json
{
    "ip_address": "192.168.1.105",
    "hostname": "My-Laptop"
}
```

**Response:**
```json
{
    "success": true,
    "message": "Device hostname updated"
}
```

**Implementation:**
```python
@app.route('/api/devices/update-name', methods=['POST'])
def update_device():
    data = request.get_json()
    ip_address = data.get('ip_address')
    hostname = data.get('hostname')
    
    if not ip_address or not hostname:
        return jsonify({'error': 'Missing required fields'}), 400
    
    success = update_device_name(ip_address, hostname)
    if success:
        return jsonify({'success': True, 'message': 'Device hostname updated'})
    else:
        return jsonify({'error': 'Device not found'}), 404
```

---

## Common Mistakes to Avoid

1. **Not importing request from flask**
   ```python
   from flask import Flask, jsonify, request  # Don't forget request!
   ```

2. **Forgetting to parse query parameters as correct type**
   ```python
   # Wrong - returns string
   limit = request.args.get('limit')
   
   # Right - returns int with default
   limit = request.args.get('limit', 10, type=int)
   ```

3. **Not handling None from database functions**
   ```python
   # Always check for None
   stats = get_realtime_stats()
   if stats is None:
       return jsonify({'error': 'Database unavailable'}), 500
   ```

4. **Returning Python objects directly**
   ```python
   # Wrong - can't serialize
   return devices
   
   # Right - use jsonify
   return jsonify({'devices': devices})
   ```

5. **Not enabling CORS**
   - Frontend running on different port won't be able to fetch
   - Always add `CORS(app)` in app.py

6. **Inconsistent response format**
   - Always return JSON with consistent structure
   - Always include error messages in error responses

---

## Example Code

### Complete app.py Example

```python
from flask import Flask, jsonify
from flask_cors import CORS
import os

def create_app():
    # Create Flask app with static folder pointing to frontend
    app = Flask(__name__, 
                static_folder='../frontend',
                static_url_path='')
    
    # Enable CORS for all routes
    CORS(app)
    
    # Register API routes
    from backend.routes import register_routes
    register_routes(app)
    
    # Serve index.html at root
    @app.route('/')
    def index():
        return app.send_static_file('index.html')
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Not found', 'code': 404}), 404
    
    @app.errorhandler(500)
    def server_error(error):
        return jsonify({'error': 'Internal server error', 'code': 500}), 500
    
    return app
```

### Complete routes.py Example Structure

```python
from flask import jsonify, request
from database.db_handler import (
    get_realtime_stats,
    get_top_devices,
    get_protocol_distribution,
    get_bandwidth_history,
    get_alerts,
    get_health_score,
    update_device_name
)

def register_routes(app):
    
    @app.route('/api/status')
    def status():
        return jsonify({
            'status': 'running',
            'version': '1.0.0'
        })
    
    @app.route('/api/stats/realtime')
    def realtime_stats():
        try:
            stats = get_realtime_stats()
            return jsonify(stats)
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/devices/top')
    def top_devices():
        limit = request.args.get('limit', 10, type=int)
        hours = request.args.get('hours', 1, type=int)
        
        # Validate parameters
        if limit < 1 or limit > 100:
            return jsonify({'error': 'limit must be 1-100'}), 400
        
        devices = get_top_devices(limit=limit, hours=hours)
        return jsonify({'devices': devices})
    
    # ... more routes
```

---

## Using AI Effectively

### Good Prompts for Your Tasks

**For app.py:**
```
"Write a Flask application factory (create_app function) that:
1. Creates a Flask instance with static_folder='../frontend'
2. Enables CORS for all origins
3. Calls register_routes(app) to add API routes
4. Has error handlers for 404 and 500 that return JSON
5. Serves index.html at the root path
Include all necessary imports"
```

**For routes.py:**
```
"Write a Flask route for GET /api/devices/top that:
1. Accepts optional 'limit' query param (default 10, validate 1-100)
2. Accepts optional 'hours' query param (default 1)
3. Calls get_top_devices(limit, hours) from database.db_handler
4. Returns JSON with 'devices' key containing the result
5. Has try/except for error handling
Include the import statement"
```

**For error handling:**
```
"Write Flask error handlers for:
1. 404 Not Found - return JSON with 'error' key and 404 status
2. 500 Internal Error - return JSON with 'error' key and 500 status
3. Custom validation errors (400) - include the specific validation message
Show how to register these with a Flask app"
```

### Testing with AI

```
"I'm testing my Flask API endpoint:

curl http://localhost:5000/api/devices/top?limit=5

Expected response:
{"devices": [...]}

Actual response:
{"error": "..."}

Here's my route code:
[paste code]

What's wrong?"
```

---

## Testing Your API

### Using curl

```bash
# Test status
curl http://localhost:5000/api/status

# Test with parameters
curl "http://localhost:5000/api/devices/top?limit=5&hours=24"

# Test POST
curl -X POST http://localhost:5000/api/devices/update-name \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "192.168.1.105", "hostname": "Test"}'
```

### Using Python requests

```python
import requests

# GET request
response = requests.get('http://localhost:5000/api/stats/realtime')
print(response.json())

# POST request
response = requests.post(
    'http://localhost:5000/api/devices/update-name',
    json={'ip_address': '192.168.1.105', 'hostname': 'Test'}
)
print(response.json())
```

### Using Browser

For GET requests, just navigate to the URL:
```
http://localhost:5000/api/status
```

---

## Coordination with Team

### With Member 5 (Database)
- **Agree on function signatures** for db_handler functions
- **Agree on return formats** (list of dicts? single dict?)
- **Test database functions** before integrating

### With Member 3 (Frontend)
- **Share API documentation** early
- **Agree on JSON response structure**
- **Test endpoints with their frontend code**

### With Member 1 (Project Lead)
- **Provide create_app() function** for main.py
- **Report any config values needed** for config.py
