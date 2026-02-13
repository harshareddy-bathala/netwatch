# Member 1 Guide: Project Lead (DevOps + ML + Integration)

## Role Summary

As the Project Lead, you are responsible for:
- **Integration:** Bringing all modules together
- **DevOps:** Project setup, dependencies, configuration
- **Machine Learning:** Anomaly detection system
- **Leadership:** Code reviews, standups, team coordination

You are the glue that holds the project together. Your code orchestrates all other components.

---

## Files You Own

| File | Purpose |
|------|---------|
| `main.py` | Application entry point, orchestration |
| `config.py` | All configuration constants |
| `requirements.txt` | Python dependencies |
| `alerts/__init__.py` | Package initialization |
| `alerts/detector.py` | ML-based anomaly detection |
| `alerts/alert_manager.py` | Alert creation and management |

---

## Detailed File Descriptions

### main.py

**Purpose:** The entry point that starts the entire NetWatch system.

**What it should do:**
1. Import all modules (database, packet_capture, alerts, backend)
2. Initialize the database on startup
3. Start the NetworkMonitor in a background thread
4. Start the AnomalyDetector in a background thread
5. Create and run the Flask app in the main thread
6. Handle graceful shutdown (Ctrl+C)

**Functions/Classes to implement:**

```python
def main():
    """Main entry point for NetWatch."""
    pass

def setup_logging():
    """Configure logging for the application."""
    pass

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully."""
    pass
```

**Key imports you'll need:**
```python
import threading
import signal
import logging
from config import *
from database.init_db import initialize_database
from packet_capture.monitor import NetworkMonitor
from alerts.detector import AnomalyDetector
from backend.app import create_app
```

---

### config.py

**Already created with actual values.** Review and adjust as needed:
- Database path
- Network interface
- Flask port
- Alert thresholds
- Protocol mappings

---

### alerts/detector.py

**Purpose:** Detect anomalies in network traffic using ML.

**What it should do:**
1. Load historical bandwidth data from database
2. Train an Isolation Forest model
3. Periodically check current stats for anomalies
4. Create alerts when anomalies are detected

**Classes/Functions to implement:**

```python
class AnomalyDetector:
    def __init__(self):
        """Initialize the Isolation Forest model."""
        pass
    
    def train_model(self, data: pd.DataFrame) -> bool:
        """Train the model on historical data."""
        pass
    
    def detect_anomaly(self, current_stats: dict) -> bool:
        """Check if current stats are anomalous."""
        pass
    
    def check_threshold_alerts(self, stats: dict) -> None:
        """Check if stats exceed configured thresholds."""
        pass
    
    def run(self):
        """Main loop - runs in background thread."""
        pass
```

**Key imports:**
```python
from sklearn.ensemble import IsolationForest
import pandas as pd
import numpy as np
import time
from database.db_handler import get_bandwidth_history, get_realtime_stats
from alerts.alert_manager import create_bandwidth_alert, create_anomaly_alert
from config import *
```

---

### alerts/alert_manager.py

**Purpose:** Create and manage system alerts.

**Functions to implement:**

```python
def create_alert(alert_type: str, severity: str, message: str) -> int:
    """Create a new alert and return its ID."""
    pass

def create_bandwidth_alert(current: float, threshold: float) -> int:
    """Create a bandwidth threshold alert."""
    pass

def create_anomaly_alert(details: dict) -> int:
    """Create an ML-detected anomaly alert."""
    pass

def get_recent_alerts(limit: int = 50, severity: str = None) -> list:
    """Get recent alerts, optionally filtered."""
    pass
```

---

## Week-by-Week Schedule

### Week 1: Project Setup
- [ ] Create GitHub repository
- [ ] Set up branch protection rules
- [ ] Review all member guides with team
- [ ] Verify config.py values for your environment
- [ ] Test that requirements.txt installs correctly
- [ ] Create initial `main.py` structure (imports, basic main function)

### Week 2: Integration Framework
- [ ] Implement `main.py` with threading structure
- [ ] Add signal handlers for graceful shutdown
- [ ] Set up logging configuration
- [ ] Create placeholder calls to other modules
- [ ] Test that Flask starts correctly
- [ ] Document startup process

### Week 3: ML Development
- [ ] Implement `AnomalyDetector.__init__`
- [ ] Implement `train_model` with Isolation Forest
- [ ] Implement `detect_anomaly` prediction
- [ ] Test with synthetic data
- [ ] Tune model parameters

### Week 4: Alert System
- [ ] Implement `alert_manager.py` functions
- [ ] Implement threshold-based alerts in detector
- [ ] Add ML-based anomaly alerts
- [ ] Integrate with database module
- [ ] Test alert creation and retrieval

### Week 5: Integration
- [ ] Integrate all modules in main.py
- [ ] Test full system end-to-end
- [ ] Fix integration bugs
- [ ] Performance tuning
- [ ] Final testing

### Week 6: Polish & Deploy
- [ ] Code review all modules
- [ ] Update documentation
- [ ] Final bug fixes
- [ ] Demo preparation
- [ ] Deployment guide

---

## Module Connections

### What You Receive (Inputs)

| From | What | Used In |
|------|------|---------|
| Member 4 | `NetworkMonitor` class | main.py |
| Member 5 | `initialize_database()` | main.py |
| Member 5 | `get_bandwidth_history()` | detector.py |
| Member 5 | `get_realtime_stats()` | detector.py |
| Member 5 | `create_alert()` | alert_manager.py |
| Member 2 | `create_app()` | main.py |

### What You Provide (Outputs)

| To | What | Purpose |
|----|------|---------|
| All | `config.py` values | Configuration constants |
| Member 2 | Alert data in database | For /api/alerts endpoint |
| System | `main.py` | Application entry point |

### Integration Points

```
main.py
  ├── calls initialize_database() from Member 5
  ├── creates NetworkMonitor from Member 4
  │     └── NetworkMonitor calls save_packet() from Member 5
  ├── creates AnomalyDetector (your code)
  │     ├── calls get_bandwidth_history() from Member 5
  │     └── calls create_alert() from Member 5
  └── creates Flask app from Member 2
        └── Flask routes call db_handler from Member 5
```

---

## Example Code Snippets

### main.py Structure

```python
import threading
import signal
import sys
import logging
from config import *

# Will be filled in as modules are ready
# from database.init_db import initialize_database
# from packet_capture.monitor import NetworkMonitor
# from alerts.detector import AnomalyDetector
# from backend.app import create_app

logger = logging.getLogger(__name__)
shutdown_event = threading.Event()

def setup_logging():
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL),
        format=LOG_FORMAT
    )

def signal_handler(signum, frame):
    logger.info("Shutdown signal received")
    shutdown_event.set()

def main():
    setup_logging()
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    logger.info("Initializing database...")
    # initialize_database()
    
    logger.info("Starting packet capture...")
    # monitor = NetworkMonitor()
    # capture_thread = threading.Thread(target=monitor.start, daemon=True)
    # capture_thread.start()
    
    logger.info("Starting anomaly detector...")
    # detector = AnomalyDetector()
    # detector_thread = threading.Thread(target=detector.run, daemon=True)
    # detector_thread.start()
    
    logger.info(f"Starting Flask server on {FLASK_HOST}:{FLASK_PORT}")
    # app = create_app()
    # app.run(host=FLASK_HOST, port=FLASK_PORT, debug=FLASK_DEBUG)

if __name__ == "__main__":
    main()
```

### Isolation Forest Basic Usage

```python
from sklearn.ensemble import IsolationForest
import numpy as np

# Training
X_train = np.array([[100], [120], [115], [105], [130]])
model = IsolationForest(contamination=0.1, random_state=42)
model.fit(X_train)

# Prediction (-1 = anomaly, 1 = normal)
X_test = np.array([[110], [500]])
predictions = model.predict(X_test)
# predictions = [1, -1] (500 is anomalous)
```

---

## Common Mistakes to Avoid

1. **Forgetting to run as admin/root**
   - Packet capture requires elevated privileges
   - Test with `sudo` on Linux/Mac

2. **Not setting threads as daemon**
   - Always use `daemon=True` so threads stop with main program
   - Otherwise, Ctrl+C won't work properly

3. **Blocking the main thread**
   - Flask should run in the main thread
   - Background tasks should be in daemon threads

4. **Not handling database not ready**
   - Check if database exists before querying
   - Initialize database before starting other components

5. **Training ML model on empty data**
   - Wait until you have enough samples
   - Use MIN_SAMPLES_FOR_ANOMALY_DETECTION from config

6. **Creating duplicate alerts**
   - Implement cooldown logic in alert_manager
   - Don't create the same alert every check cycle

---

## Using AI Effectively

### Good Prompts for Your Tasks

**For main.py:**
```
"Write a Python main.py that:
1. Sets up logging with configurable level
2. Creates a NetworkMonitor instance and starts it in a daemon thread
3. Creates an AnomalyDetector instance and starts it in another daemon thread
4. Runs a Flask app in the main thread
5. Handles SIGINT and SIGTERM for graceful shutdown
6. Uses these imports: [list your actual imports]"
```

**For anomaly detection:**
```
"Write a Python class AnomalyDetector that:
1. Uses IsolationForest from sklearn
2. Has a train_model method that takes a pandas DataFrame with 'bandwidth' column
3. Has a detect_anomaly method that takes current_bandwidth as float
4. Has a run method that loops every 60 seconds, fetching data and checking for anomalies
5. Creates alerts when anomalies are detected
Include type hints and docstrings"
```

**For alert manager:**
```
"Write Python functions for managing alerts:
1. create_alert(alert_type, severity, message) - saves to database
2. create_bandwidth_alert(current, threshold) - creates formatted bandwidth alert
3. Implement a cooldown to prevent duplicate alerts within 5 minutes
Include logging for each alert created"
```

### Debugging with AI

```
"I'm getting this error in my NetWatch project:
[paste error]

Here's my code:
[paste relevant code]

The system architecture is: [brief description]
What's wrong and how do I fix it?"
```

---

## Leadership Tips

1. **Daily standups (15 min max):**
   - What did you do yesterday?
   - What are you doing today?
   - Any blockers?

2. **Code reviews:**
   - Review within 24 hours
   - Be constructive, not critical
   - Focus on bugs and maintainability

3. **Integration days:**
   - Schedule specific days to merge code
   - Be available to help with merge conflicts

4. **Documentation:**
   - Ensure README stays updated
   - Update ARCHITECTURE.md as system evolves
