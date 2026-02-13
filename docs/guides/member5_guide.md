# Member 5 Guide: Database + Documentation (Data Layer + Docs)

## Role Summary

As the Database + Documentation Developer, you are responsible for:
- **Database Schema:** Designing and creating tables
- **Database Operations:** All CRUD functions for the system
- **Documentation:** Writing all project documentation
- **Data Integrity:** Ensuring data is stored and retrieved correctly

Your database functions are used by EVERY other module in the system.

---

## Files You Own

### Database Files

| File | Purpose |
|------|---------|
| `database/__init__.py` | Package initialization |
| `database/schema.sql` | Table definitions |
| `database/init_db.py` | Database initialization |
| `database/db_handler.py` | All database operations |

### Documentation Files

| File | Purpose |
|------|---------|
| `docs/README.md` | Documentation index |
| `docs/ARCHITECTURE.md` | System architecture |
| `docs/API_DOCS.md` | API reference |
| `docs/SETUP_GUIDE.md` | Installation guide |
| `docs/USER_MANUAL.md` | User guide |
| `docs/CONTRIBUTING.md` | Contribution guidelines |

---

## Detailed File Descriptions

### database/schema.sql

**Purpose:** Define all database tables.

**Tables to create:**

```sql
-- Table: devices
-- Stores known network devices
CREATE TABLE devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL UNIQUE,
    hostname TEXT,
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    total_bytes INTEGER DEFAULT 0
);

-- Table: traffic_summary
-- Stores every captured packet summary
CREATE TABLE traffic_summary (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP NOT NULL,
    source_ip TEXT NOT NULL,
    dest_ip TEXT NOT NULL,
    protocol TEXT NOT NULL,
    bytes_transferred INTEGER NOT NULL,
    source_port INTEGER,
    dest_port INTEGER
);

-- Table: alerts
-- Stores system alerts
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP NOT NULL,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    resolved BOOLEAN DEFAULT 0,
    resolved_at TIMESTAMP
);

-- Indexes for performance
CREATE INDEX idx_traffic_timestamp ON traffic_summary(timestamp);
CREATE INDEX idx_traffic_source ON traffic_summary(source_ip);
CREATE INDEX idx_traffic_dest ON traffic_summary(dest_ip);
CREATE INDEX idx_devices_ip ON devices(ip_address);
CREATE INDEX idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX idx_alerts_severity ON alerts(severity);
```

---

### database/init_db.py

**Purpose:** Create the database file with schema.

**Functions to implement:**

```python
def initialize_database() -> bool:
    """Create database with schema if it doesn't exist."""
    pass

def reset_database(confirm: bool = False) -> bool:
    """Delete and recreate database (requires confirm=True)."""
    pass

def check_database_exists() -> bool:
    """Check if database file exists."""
    pass
```

---

### database/db_handler.py

**Purpose:** ALL database operations that other modules use.

**Functions to implement:**

```python
# Connection helper
@contextmanager
def get_connection():
    """Get database connection with proper cleanup."""
    pass

# Packet/Traffic functions
def save_packet(packet_data: dict) -> int:
    """Save packet and update device stats."""
    pass

def get_bandwidth_history(hours: int = 1) -> list:
    """Get bandwidth aggregated by minute."""
    pass

# Device functions
def get_top_devices(limit: int = 10, hours: int = 1) -> list:
    """Get top N devices by bandwidth."""
    pass

def update_device_name(ip_address: str, new_name: str) -> bool:
    """Update device hostname."""
    pass

# Protocol functions
def get_protocol_distribution(hours: int = 1) -> list:
    """Get protocol statistics."""
    pass

# Stats functions
def get_realtime_stats() -> dict:
    """Get current real-time statistics."""
    pass

def get_health_score() -> dict:
    """Calculate network health score."""
    pass

# Alert functions
def create_alert(alert_type: str, severity: str, message: str) -> int:
    """Create a new alert."""
    pass

def get_alerts(limit: int = 50, severity: str = None) -> list:
    """Get recent alerts with optional filter."""
    pass
```

---

## Week-by-Week Schedule

### Week 1: Schema & Documentation
- [ ] Write schema.sql with all tables
- [ ] Implement init_db.py
- [ ] Test database creation
- [ ] Write docs/README.md
- [ ] Write docs/ARCHITECTURE.md

### Week 2: Core DB Functions
- [ ] Implement get_connection context manager
- [ ] Implement save_packet()
- [ ] Implement get_bandwidth_history()
- [ ] Test with sample data
- [ ] Write docs/SETUP_GUIDE.md

### Week 3: Device & Protocol Functions
- [ ] Implement get_top_devices()
- [ ] Implement update_device_name()
- [ ] Implement get_protocol_distribution()
- [ ] Test all device functions
- [ ] Write docs/API_DOCS.md

### Week 4: Stats & Alerts
- [ ] Implement get_realtime_stats()
- [ ] Implement get_health_score()
- [ ] Implement create_alert()
- [ ] Implement get_alerts()
- [ ] Write docs/USER_MANUAL.md

### Week 5: Integration & Testing
- [ ] Test with Member 2 (Backend)
- [ ] Test with Member 4 (Packet Capture)
- [ ] Fix any issues
- [ ] Write docs/CONTRIBUTING.md
- [ ] Write all member guides

### Week 6: Polish
- [ ] Final testing
- [ ] Update all documentation
- [ ] Code cleanup
- [ ] Demo preparation

---

## Module Connections

### Who Calls Your Functions

| Module | Functions Used |
|--------|---------------|
| Member 4 (Packet Capture) | `save_packet()` |
| Member 2 (Backend) | `get_top_devices()`, `get_bandwidth_history()`, `get_protocol_distribution()`, `get_realtime_stats()`, `get_health_score()`, `get_alerts()`, `update_device_name()` |
| Member 1 (Alerts) | `create_alert()`, `get_bandwidth_history()`, `get_realtime_stats()` |
| Member 1 (Main) | `initialize_database()` |

### Data Flow

```
Member 4 (Packet Capture)
      │
      │ packet_data dict
      ▼
save_packet()
      │
      │ INSERT into traffic_summary
      │ UPSERT into devices
      ▼
netwatch.db
      │
      ▼
get_* functions
      │
      │ SELECT queries
      ▼
Member 2 (Backend)
```

---

## SQLite Crash Course

### Connecting to SQLite

```python
import sqlite3

# Connect to database (creates file if not exists)
conn = sqlite3.connect('netwatch.db')

# Create cursor
cursor = conn.cursor()

# Execute query
cursor.execute("SELECT * FROM devices")

# Fetch results
rows = cursor.fetchall()

# Commit changes
conn.commit()

# Close connection
conn.close()
```

### Context Manager Pattern

```python
from contextlib import contextmanager

@contextmanager
def get_connection():
    conn = sqlite3.connect('netwatch.db')
    conn.row_factory = sqlite3.Row  # Access columns by name
    try:
        yield conn
    finally:
        conn.close()

# Usage
with get_connection() as conn:
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices")
    rows = cursor.fetchall()
```

### Common Queries

```python
# Insert
cursor.execute(
    "INSERT INTO devices (ip_address, first_seen, last_seen) VALUES (?, ?, ?)",
    (ip, now, now)
)
device_id = cursor.lastrowid

# Update
cursor.execute(
    "UPDATE devices SET hostname = ? WHERE ip_address = ?",
    (hostname, ip)
)

# Select with aggregation
cursor.execute("""
    SELECT protocol, COUNT(*) as count, SUM(bytes_transferred) as bytes
    FROM traffic_summary
    WHERE timestamp > ?
    GROUP BY protocol
    ORDER BY bytes DESC
""", (one_hour_ago,))
```

---

## Example Code

### Complete init_db.py

```python
import sqlite3
import os
import logging

from config import DATABASE_PATH

logger = logging.getLogger(__name__)

def initialize_database() -> bool:
    """
    Initialize the database with the schema.
    Creates tables if they don't exist.
    
    Returns:
        True if successful, False otherwise
    """
    try:
        # Get path to schema.sql
        schema_path = os.path.join(
            os.path.dirname(__file__), 
            'schema.sql'
        )
        
        # Read schema
        with open(schema_path, 'r') as f:
            schema = f.read()
        
        # Connect and execute schema
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.executescript(schema)
        conn.commit()
        conn.close()
        
        logger.info(f"Database initialized at {DATABASE_PATH}")
        return True
        
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        return False

def reset_database(confirm: bool = False) -> bool:
    """
    Delete and recreate the database.
    
    Args:
        confirm: Must be True to prevent accidental data loss
    
    Returns:
        True if successful, False otherwise
    """
    if not confirm:
        logger.warning("reset_database requires confirm=True")
        return False
    
    try:
        # Delete existing database
        if os.path.exists(DATABASE_PATH):
            os.remove(DATABASE_PATH)
            logger.info(f"Deleted existing database: {DATABASE_PATH}")
        
        # Recreate
        return initialize_database()
        
    except Exception as e:
        logger.error(f"Database reset failed: {e}")
        return False

def check_database_exists() -> bool:
    """Check if the database file exists."""
    return os.path.exists(DATABASE_PATH)


if __name__ == "__main__":
    import sys
    
    if "--reset" in sys.argv:
        print("WARNING: This will delete all data!")
        response = input("Type 'yes' to confirm: ")
        if response.lower() == 'yes':
            reset_database(confirm=True)
        else:
            print("Cancelled")
    else:
        initialize_database()
```

### Complete db_handler.py

```python
import sqlite3
from datetime import datetime, timedelta
from contextlib import contextmanager
import logging

from config import DATABASE_PATH, DATABASE_TIMEOUT

logger = logging.getLogger(__name__)

@contextmanager
def get_connection():
    """
    Get database connection with proper cleanup.
    Uses row_factory for dict-like access.
    """
    conn = sqlite3.connect(DATABASE_PATH, timeout=DATABASE_TIMEOUT)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def save_packet(packet_data: dict) -> int:
    """
    Save a packet to the database and update device stats.
    
    Args:
        packet_data: Dict with timestamp, source_ip, dest_ip, 
                     protocol, bytes, source_port, dest_port
    
    Returns:
        ID of inserted traffic record
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        now = datetime.now().isoformat()
        
        # Insert traffic record
        cursor.execute("""
            INSERT INTO traffic_summary 
            (timestamp, source_ip, dest_ip, protocol, bytes_transferred, source_port, dest_port)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            packet_data['timestamp'].isoformat() if isinstance(packet_data['timestamp'], datetime) else packet_data['timestamp'],
            packet_data['source_ip'],
            packet_data['dest_ip'],
            packet_data['protocol'],
            packet_data['bytes'],
            packet_data.get('source_port'),
            packet_data.get('dest_port')
        ))
        traffic_id = cursor.lastrowid
        
        # Update source device
        cursor.execute("""
            INSERT INTO devices (ip_address, first_seen, last_seen, total_bytes)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(ip_address) DO UPDATE SET
                last_seen = excluded.last_seen,
                total_bytes = total_bytes + excluded.total_bytes
        """, (packet_data['source_ip'], now, now, packet_data['bytes']))
        
        conn.commit()
        return traffic_id


def get_top_devices(limit: int = 10, hours: int = 1) -> list:
    """
    Get top N devices by bandwidth in the last X hours.
    
    Returns:
        List of dicts with ip_address, hostname, total_bytes, last_seen
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
        
        cursor.execute("""
            SELECT 
                ip_address,
                hostname,
                total_bytes,
                last_seen
            FROM devices
            WHERE last_seen > ?
            ORDER BY total_bytes DESC
            LIMIT ?
        """, (cutoff, limit))
        
        return [dict(row) for row in cursor.fetchall()]


def get_bandwidth_history(hours: int = 1) -> list:
    """
    Get bandwidth aggregated by minute for the last X hours.
    
    Returns:
        List of dicts with timestamp and bytes_per_second
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
        
        cursor.execute("""
            SELECT 
                strftime('%Y-%m-%dT%H:%M:00', timestamp) as minute,
                SUM(bytes_transferred) as total_bytes
            FROM traffic_summary
            WHERE timestamp > ?
            GROUP BY minute
            ORDER BY minute ASC
        """, (cutoff,))
        
        results = []
        for row in cursor.fetchall():
            results.append({
                'timestamp': row['minute'],
                'bytes_per_second': row['total_bytes'] // 60  # Average per second
            })
        
        return results


def get_protocol_distribution(hours: int = 1) -> list:
    """
    Get protocol distribution statistics.
    
    Returns:
        List of dicts with name, count, bytes, percentage
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
        
        cursor.execute("""
            SELECT 
                protocol,
                COUNT(*) as count,
                SUM(bytes_transferred) as bytes
            FROM traffic_summary
            WHERE timestamp > ?
            GROUP BY protocol
            ORDER BY bytes DESC
        """, (cutoff,))
        
        rows = cursor.fetchall()
        total_count = sum(row['count'] for row in rows)
        
        return [{
            'name': row['protocol'],
            'count': row['count'],
            'bytes': row['bytes'],
            'percentage': round(row['count'] / total_count * 100, 1) if total_count > 0 else 0
        } for row in rows]


def get_realtime_stats() -> dict:
    """
    Get current real-time statistics.
    
    Returns:
        Dict with bandwidth_bps, active_devices, packets_per_second
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        one_minute_ago = (datetime.now() - timedelta(minutes=1)).isoformat()
        five_minutes_ago = (datetime.now() - timedelta(minutes=5)).isoformat()
        
        # Get bandwidth in last minute
        cursor.execute("""
            SELECT COALESCE(SUM(bytes_transferred), 0) as bytes
            FROM traffic_summary
            WHERE timestamp > ?
        """, (one_minute_ago,))
        bytes_last_minute = cursor.fetchone()['bytes']
        
        # Get packet count in last minute
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM traffic_summary
            WHERE timestamp > ?
        """, (one_minute_ago,))
        packets_last_minute = cursor.fetchone()['count']
        
        # Get active devices
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM devices
            WHERE last_seen > ?
        """, (five_minutes_ago,))
        active_devices = cursor.fetchone()['count']
        
        return {
            'bandwidth_bps': bytes_last_minute // 60,  # Per second
            'active_devices': active_devices,
            'packets_per_second': packets_last_minute // 60
        }


def get_health_score() -> dict:
    """
    Calculate and return network health score (0-100).
    
    Returns:
        Dict with score, status, and factors
    """
    stats = get_realtime_stats()
    
    # Simple scoring algorithm
    score = 100
    factors = {}
    
    # Bandwidth factor (deduct if very high)
    if stats['bandwidth_bps'] > 50_000_000:  # > 50 MB/s
        score -= 30
        factors['bandwidth'] = {'value': stats['bandwidth_bps'], 'status': 'critical'}
    elif stats['bandwidth_bps'] > 10_000_000:  # > 10 MB/s
        score -= 15
        factors['bandwidth'] = {'value': stats['bandwidth_bps'], 'status': 'warning'}
    else:
        factors['bandwidth'] = {'value': stats['bandwidth_bps'], 'status': 'good'}
    
    # Device count factor
    if stats['active_devices'] > 100:
        score -= 20
        factors['devices'] = {'value': stats['active_devices'], 'status': 'critical'}
    elif stats['active_devices'] > 50:
        score -= 10
        factors['devices'] = {'value': stats['active_devices'], 'status': 'warning'}
    else:
        factors['devices'] = {'value': stats['active_devices'], 'status': 'good'}
    
    # Ensure score is in range
    score = max(0, min(100, score))
    
    # Determine status
    if score >= 80:
        status = 'good'
    elif score >= 50:
        status = 'warning'
    else:
        status = 'critical'
    
    return {
        'score': score,
        'status': status,
        'factors': factors
    }


def create_alert(alert_type: str, severity: str, message: str) -> int:
    """
    Create a new alert.
    
    Args:
        alert_type: Type of alert (bandwidth, anomaly, device_count, health)
        severity: Severity level (info, warning, critical)
        message: Alert message
    
    Returns:
        ID of created alert
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        now = datetime.now().isoformat()
        
        cursor.execute("""
            INSERT INTO alerts (timestamp, alert_type, severity, message)
            VALUES (?, ?, ?, ?)
        """, (now, alert_type, severity, message))
        
        conn.commit()
        return cursor.lastrowid


def get_alerts(limit: int = 50, severity: str = None) -> list:
    """
    Get recent alerts with optional severity filter.
    
    Returns:
        List of alert dicts
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        
        if severity:
            cursor.execute("""
                SELECT id, timestamp, alert_type, severity, message, resolved, resolved_at
                FROM alerts
                WHERE severity = ?
                ORDER BY timestamp DESC
                LIMIT ?
            """, (severity, limit))
        else:
            cursor.execute("""
                SELECT id, timestamp, alert_type, severity, message, resolved, resolved_at
                FROM alerts
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
        
        return [dict(row) for row in cursor.fetchall()]


def update_device_name(ip_address: str, new_name: str) -> bool:
    """
    Update a device's hostname.
    
    Returns:
        True if updated, False if device not found
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE devices
            SET hostname = ?
            WHERE ip_address = ?
        """, (new_name, ip_address))
        
        conn.commit()
        return cursor.rowcount > 0
```

---

## Common Mistakes to Avoid

1. **Not closing connections**
   ```python
   # Wrong - connection leak
   conn = sqlite3.connect('db.sqlite')
   cursor.execute(...)
   # conn never closed!
   
   # Right - use context manager
   with get_connection() as conn:
       cursor.execute(...)
   # Connection auto-closed
   ```

2. **SQL injection vulnerability**
   ```python
   # WRONG - Never do this!
   cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
   
   # RIGHT - Use parameterized queries
   cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
   ```

3. **Forgetting to commit**
   ```python
   cursor.execute("INSERT INTO ...")
   conn.commit()  # Don't forget this!
   ```

4. **Not handling None in optional fields**
   ```python
   # Ports can be None for ICMP packets
   cursor.execute("""
       INSERT INTO traffic_summary (source_port, ...)
       VALUES (?, ...)
   """, (packet_data.get('source_port'),))  # .get() returns None if missing
   ```

5. **Using fetchall() for large results**
   ```python
   # For large result sets, iterate instead
   for row in cursor:
       process(row)
   ```

---

## Using AI Effectively

### Good Prompts for Your Tasks

**For schema design:**
```
"Write a SQLite schema for a network monitoring database with:
1. devices table: id, ip_address (unique), hostname, first_seen, last_seen, total_bytes
2. traffic_summary table: id, timestamp, source_ip, dest_ip, protocol, bytes_transferred, ports
3. alerts table: id, timestamp, alert_type, severity, message, resolved
Include appropriate indexes for performance
Use SQLite-compatible syntax"
```

**For db_handler functions:**
```
"Write a Python function get_protocol_distribution(hours=1) that:
1. Uses SQLite with a context manager for connection
2. Queries traffic_summary for the last X hours
3. Groups by protocol
4. Returns list of dicts with name, count, bytes, and percentage
5. Handles empty results
Include the full function with docstring"
```

**For aggregation queries:**
```
"Write a SQLite query that:
1. Selects from traffic_summary table
2. Groups data by minute (using strftime)
3. Calculates sum of bytes_transferred per minute
4. Filters to last 24 hours
5. Orders by time ascending
Explain what strftime format to use for minute grouping"
```

---

## Documentation Responsibilities

As the documentation owner, you should:

1. **Keep docs updated** as code changes
2. **Review API changes** with Member 2 and update API_DOCS.md
3. **Update ARCHITECTURE.md** when system structure changes
4. **Add troubleshooting** as issues are discovered
5. **Write member guides** that are clear and actionable

### Documentation Checklist

- [ ] README.md covers project overview
- [ ] SETUP_GUIDE.md works on all platforms
- [ ] API_DOCS.md matches actual API
- [ ] USER_MANUAL.md is user-friendly
- [ ] ARCHITECTURE.md diagram is accurate
- [ ] Member guides are complete and helpful

---

## Coordination with Team

### With All Members
- **Provide database functions** they need
- **Agree on data formats** (what dict keys, what types)
- **Test your functions** with their code

### With Member 2 (Backend)
- **Share function signatures** early
- **Agree on return value formats**
- **Document any error cases**

### With Member 4 (Packet Capture)
- **Agree on save_packet() input format**
- **Handle any missing fields gracefully**
- **Consider performance** (many inserts per second)

### With Member 1 (Project Lead)
- **Provide initialize_database()** for main.py
- **Provide alert functions** for anomaly detection
- **Report any schema changes**
