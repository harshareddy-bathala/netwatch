# Member 4 Guide: Packet Capture Developer (Network Analysis)

## Role Summary

As the Packet Capture Developer, you are responsible for:
- **Packet Capture:** Using Scapy to sniff network packets
- **Packet Parsing:** Extracting useful information from raw packets
- **Protocol Detection:** Identifying protocols by port numbers
- **Threading:** Running capture in background without blocking

Your module is the data source for the entire system.

---

## Files You Own

| File | Purpose |
|------|---------|
| `packet_capture/__init__.py` | Package initialization |
| `packet_capture/monitor.py` | Main capture engine |
| `packet_capture/parser.py` | Packet parsing logic |
| `packet_capture/protocols.py` | Protocol detection |

---

## Detailed File Descriptions

### packet_capture/monitor.py

**Purpose:** The main packet capture engine using Scapy.

**What it should contain:**

```python
class NetworkMonitor:
    def __init__(self, interface=None):
        """Initialize with network interface."""
        pass
    
    def start(self):
        """Start packet capture and processing threads."""
        pass
    
    def stop(self):
        """Stop packet capture gracefully."""
        pass
    
    def _capture_packets(self):
        """Main capture loop using Scapy sniff."""
        pass
    
    def _packet_callback(self, packet):
        """Callback for each captured packet."""
        pass
    
    def _process_packets(self):
        """Process packets from queue and save to database."""
        pass
```

---

### packet_capture/parser.py

**Purpose:** Parse raw Scapy packets into structured data.

**What it should contain:**

```python
def parse_packet(packet) -> dict:
    """
    Parse a raw Scapy packet and return structured data.
    
    Returns:
        dict with: timestamp, source_ip, dest_ip, source_port,
                   dest_port, protocol, bytes, raw_protocol
        OR None if packet cannot be parsed
    """
    pass

def extract_ip_info(packet) -> tuple:
    """Extract source and destination IP addresses."""
    pass

def extract_port_info(packet) -> tuple:
    """Extract source and destination ports."""
    pass

def get_packet_size(packet) -> int:
    """Get packet size in bytes."""
    pass
```

---

### packet_capture/protocols.py

**Purpose:** Detect application-layer protocols from port numbers.

**What it should contain:**

```python
def detect_protocol(src_port, dst_port, raw_protocol='TCP') -> str:
    """
    Detect application protocol from port numbers.
    
    Returns:
        Protocol name (e.g., 'HTTP', 'HTTPS', 'DNS', 'TCP')
    """
    pass

def get_protocol_by_port(port) -> str:
    """Look up protocol by port number."""
    pass

def is_http_traffic(src_port, dst_port) -> bool:
    """Check if traffic is HTTP/HTTPS."""
    pass
```

---

## Week-by-Week Schedule

### Week 1: Scapy Basics
- [ ] Install Scapy and test on your machine
- [ ] Learn Scapy sniff() function
- [ ] Test capturing packets manually
- [ ] Understand packet layers (Ether, IP, TCP, UDP)
- [ ] Write simple capture script

### Week 2: Parser Development
- [ ] Implement parser.py functions
- [ ] Extract IP addresses from packets
- [ ] Extract port numbers from TCP/UDP packets
- [ ] Handle packets without IP layer
- [ ] Test with different packet types

### Week 3: Protocol Detection
- [ ] Implement protocols.py
- [ ] Create port-to-protocol mapping
- [ ] Test protocol detection
- [ ] Handle edge cases (unknown ports)

### Week 4: NetworkMonitor Class
- [ ] Implement NetworkMonitor.__init__
- [ ] Implement start() and stop()
- [ ] Implement _capture_packets with sniff()
- [ ] Add threading for background capture
- [ ] Test thread management

### Week 5: Integration
- [ ] Add packet queue for buffering
- [ ] Implement _process_packets loop
- [ ] Integrate with database module (save_packet)
- [ ] Test with live traffic
- [ ] Handle permission errors

### Week 6: Polish
- [ ] Add logging
- [ ] Improve error handling
- [ ] Performance optimization
- [ ] Final testing
- [ ] Documentation

---

## Module Connections

### What You Receive (Inputs)

| From | What | Used In |
|------|------|---------|
| Member 1 | `NETWORK_INTERFACE` from config | monitor.py |
| Member 1 | `PROTOCOL_PORTS` from config | protocols.py |
| Network | Raw packets | monitor.py |

### What You Provide (Outputs)

| To | What | Purpose |
|----|------|---------|
| Member 5 | Parsed packet dict | Saved to database |
| Member 1 | `NetworkMonitor` class | Started in main.py |

### Data Flow

```
Network Interface
      │
      │ Raw packet
      ▼
monitor.py (_capture_packets)
      │
      │ Scapy packet object
      ▼
parser.py (parse_packet)
      │
      │ Extract IPs, ports, size
      ▼
protocols.py (detect_protocol)
      │
      │ Add protocol name
      ▼
monitor.py (packet queue)
      │
      │ Parsed dict
      ▼
db_handler.save_packet() [Member 5]
```

---

## Scapy Crash Course

### Installing Scapy

```bash
pip install scapy
```

**Windows:** Also install Npcap from https://npcap.com

### Basic Sniffing

```python
from scapy.all import sniff, IP, TCP, UDP

# Capture 10 packets
packets = sniff(count=10)

# Print packet summary
for pkt in packets:
    print(pkt.summary())
```

### Callback-based Sniffing

```python
def packet_callback(packet):
    if packet.haslayer(IP):
        print(f"{packet[IP].src} -> {packet[IP].dst}")

# Continuous sniff with callback
sniff(prn=packet_callback, store=False)
```

### Accessing Packet Layers

```python
from scapy.all import IP, TCP, UDP, Ether

# Check if layer exists
if packet.haslayer(IP):
    ip_layer = packet[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst

if packet.haslayer(TCP):
    tcp_layer = packet[TCP]
    src_port = tcp_layer.sport
    dst_port = tcp_layer.dport

# Get packet size
size = len(packet)
```

### Specifying Interface

```python
# List available interfaces
from scapy.all import get_if_list
print(get_if_list())

# Sniff on specific interface
sniff(iface="eth0", prn=callback)
```

---

## Example Code

### Complete monitor.py

```python
from scapy.all import sniff, IP, get_if_list
from queue import Queue, Empty
import threading
import logging
from datetime import datetime

from config import NETWORK_INTERFACE
from packet_capture.parser import parse_packet
# from database.db_handler import save_packet  # Uncomment when Member 5 is ready

logger = logging.getLogger(__name__)

class NetworkMonitor:
    def __init__(self, interface=None):
        """
        Initialize the network monitor.
        
        Args:
            interface: Network interface name (e.g., 'eth0', 'wlan0')
                       If None, uses config default or auto-detect
        """
        self.interface = interface or NETWORK_INTERFACE
        self.packet_queue = Queue()
        self.running = False
        self.capture_thread = None
        self.processor_thread = None
        
        # Log available interfaces
        logger.info(f"Available interfaces: {get_if_list()}")
        logger.info(f"Using interface: {self.interface}")
    
    def start(self):
        """Start packet capture and processing threads."""
        if self.running:
            logger.warning("Monitor already running")
            return
        
        self.running = True
        
        # Start capture thread
        self.capture_thread = threading.Thread(
            target=self._capture_packets,
            daemon=True
        )
        self.capture_thread.start()
        
        # Start processor thread
        self.processor_thread = threading.Thread(
            target=self._process_packets,
            daemon=True
        )
        self.processor_thread.start()
        
        logger.info("Network monitor started")
    
    def stop(self):
        """Stop packet capture gracefully."""
        self.running = False
        logger.info("Network monitor stopping...")
        
        # Wait for threads to finish
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
        if self.processor_thread:
            self.processor_thread.join(timeout=2)
        
        logger.info("Network monitor stopped")
    
    def _capture_packets(self):
        """Main capture loop using Scapy sniff."""
        try:
            sniff(
                iface=self.interface,
                prn=self._packet_callback,
                store=False,
                stop_filter=lambda x: not self.running
            )
        except PermissionError:
            logger.error(
                "Permission denied. Run with administrator/root privileges."
            )
        except Exception as e:
            logger.error(f"Capture error: {e}")
    
    def _packet_callback(self, packet):
        """Callback for each captured packet."""
        if not self.running:
            return
        
        # Parse packet
        parsed = parse_packet(packet)
        if parsed:
            self.packet_queue.put(parsed)
    
    def _process_packets(self):
        """Process packets from queue and save to database."""
        while self.running:
            try:
                # Get packet with timeout to allow checking running flag
                parsed = self.packet_queue.get(timeout=1)
                
                # Save to database
                # save_packet(parsed)  # Uncomment when Member 5 is ready
                
                logger.debug(
                    f"Packet: {parsed['source_ip']} -> {parsed['dest_ip']} "
                    f"({parsed['protocol']}, {parsed['bytes']} bytes)"
                )
                
            except Empty:
                continue
            except Exception as e:
                logger.error(f"Processing error: {e}")
```

### Complete parser.py

```python
from scapy.all import IP, TCP, UDP, ICMP
from datetime import datetime
import logging

from packet_capture.protocols import detect_protocol

logger = logging.getLogger(__name__)

def parse_packet(packet) -> dict:
    """
    Parse a raw Scapy packet and return structured data.
    
    Args:
        packet: Raw Scapy packet object
    
    Returns:
        dict with packet info or None if not parseable
    """
    # Must have IP layer
    if not packet.haslayer(IP):
        return None
    
    ip_layer = packet[IP]
    
    # Extract basic info
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    size = get_packet_size(packet)
    
    # Extract port info (may be None for ICMP, etc.)
    src_port, dst_port = extract_port_info(packet)
    
    # Determine raw protocol
    if packet.haslayer(TCP):
        raw_protocol = 'TCP'
    elif packet.haslayer(UDP):
        raw_protocol = 'UDP'
    elif packet.haslayer(ICMP):
        raw_protocol = 'ICMP'
    else:
        raw_protocol = 'OTHER'
    
    # Detect application protocol
    protocol = detect_protocol(src_port, dst_port, raw_protocol)
    
    return {
        'timestamp': datetime.now(),
        'source_ip': src_ip,
        'dest_ip': dst_ip,
        'source_port': src_port,
        'dest_port': dst_port,
        'protocol': protocol,
        'bytes': size,
        'raw_protocol': raw_protocol
    }

def extract_ip_info(packet) -> tuple:
    """
    Extract source and destination IP addresses.
    
    Returns:
        (src_ip, dst_ip) tuple or (None, None)
    """
    if packet.haslayer(IP):
        return (packet[IP].src, packet[IP].dst)
    return (None, None)

def extract_port_info(packet) -> tuple:
    """
    Extract source and destination ports.
    
    Returns:
        (src_port, dst_port) tuple or (None, None)
    """
    if packet.haslayer(TCP):
        return (packet[TCP].sport, packet[TCP].dport)
    elif packet.haslayer(UDP):
        return (packet[UDP].sport, packet[UDP].dport)
    return (None, None)

def get_packet_size(packet) -> int:
    """
    Get packet size in bytes.
    
    Returns:
        Size in bytes
    """
    return len(packet)
```

### Complete protocols.py

```python
from config import PROTOCOL_PORTS

def detect_protocol(src_port, dst_port, raw_protocol='TCP') -> str:
    """
    Detect application-layer protocol from port numbers.
    
    Args:
        src_port: Source port number (can be None)
        dst_port: Destination port number (can be None)
        raw_protocol: Transport protocol ('TCP', 'UDP', 'ICMP')
    
    Returns:
        Protocol name string (e.g., 'HTTP', 'HTTPS', 'DNS', 'TCP')
    """
    # Check destination port first (more common)
    if dst_port and dst_port in PROTOCOL_PORTS:
        return PROTOCOL_PORTS[dst_port]
    
    # Check source port (for response packets)
    if src_port and src_port in PROTOCOL_PORTS:
        return PROTOCOL_PORTS[src_port]
    
    # Fall back to raw protocol
    return raw_protocol or 'UNKNOWN'

def get_protocol_by_port(port) -> str:
    """
    Look up protocol by port number.
    
    Args:
        port: Port number
    
    Returns:
        Protocol name or None
    """
    if port is None:
        return None
    return PROTOCOL_PORTS.get(port)

def is_http_traffic(src_port, dst_port) -> bool:
    """
    Check if traffic is HTTP or HTTPS.
    
    Returns:
        True if HTTP/HTTPS traffic
    """
    http_ports = {80, 443, 8080, 8443}
    return (src_port in http_ports) or (dst_port in http_ports)

def get_protocol_category(protocol_name) -> str:
    """
    Get category for a protocol.
    
    Returns:
        Category string: 'web', 'email', 'file_transfer', 'remote', 'other'
    """
    categories = {
        'web': ['HTTP', 'HTTPS', 'HTTP-ALT', 'HTTPS-ALT'],
        'email': ['SMTP', 'SMTPS', 'POP3', 'POP3S', 'IMAP', 'IMAPS'],
        'file_transfer': ['FTP', 'FTP-DATA'],
        'remote': ['SSH', 'TELNET', 'RDP'],
        'dns': ['DNS'],
        'database': ['MySQL', 'PostgreSQL']
    }
    
    for category, protocols in categories.items():
        if protocol_name in protocols:
            return category
    
    return 'other'
```

---

## Common Mistakes to Avoid

1. **Not checking for IP layer**
   ```python
   # Wrong - will crash on non-IP packets
   ip = packet[IP]
   
   # Right - check first
   if packet.haslayer(IP):
       ip = packet[IP]
   ```

2. **Forgetting admin/root privileges**
   - Scapy needs elevated privileges to capture packets
   - Test with `sudo` on Linux/Mac
   - Run as Administrator on Windows

3. **Not using stop_filter**
   ```python
   # sniff() blocks forever without stop_filter
   sniff(
       prn=callback,
       stop_filter=lambda x: not self.running  # Allows graceful stop
   )
   ```

4. **Not handling the queue properly**
   ```python
   # Use timeout to allow checking running flag
   try:
       item = queue.get(timeout=1)
   except Empty:
       continue  # Check running flag and loop
   ```

5. **Blocking the capture thread**
   - Database writes can be slow
   - Use a queue to decouple capture from storage

6. **Not handling missing ports**
   ```python
   # ICMP doesn't have ports
   if packet.haslayer(TCP):
       port = packet[TCP].dport
   elif packet.haslayer(UDP):
       port = packet[UDP].dport
   else:
       port = None  # Handle this case!
   ```

---

## Using AI Effectively

### Good Prompts for Your Tasks

**For Scapy basics:**
```
"Write a Python function using Scapy that:
1. Sniffs packets on a given interface
2. Uses a callback function for each packet
3. Extracts: source IP, destination IP, source port, destination port, packet size
4. Returns None for non-IP packets
5. Handles both TCP and UDP packets
Include all necessary imports from scapy.all"
```

**For threading:**
```
"Write a Python class NetworkMonitor that:
1. Has start() method that begins packet capture in a daemon thread
2. Has stop() method that gracefully stops capture
3. Uses a Queue to buffer captured packets
4. Has a processor thread that reads from queue
5. Uses a running flag to control the loops
Include proper thread synchronization"
```

**For protocol detection:**
```
"Write a Python function detect_protocol(src_port, dst_port) that:
1. Takes source and destination port numbers
2. Maps common ports to protocol names:
   - 80 -> HTTP, 443 -> HTTPS, 53 -> DNS, 22 -> SSH
3. Returns 'TCP' if no known port matches
4. Handles None values for ports
Include the port mapping dictionary"
```

---

## Testing Your Code

### Test Without Full System

```python
# test_capture.py - Simple test script
from scapy.all import sniff, IP

def test_callback(packet):
    if packet.haslayer(IP):
        print(f"{packet[IP].src} -> {packet[IP].dst}")

# Capture 5 packets for testing
sniff(count=5, prn=test_callback)
```

### Test Parser with Crafted Packets

```python
from scapy.all import IP, TCP, Ether
from packet_capture.parser import parse_packet

# Create test packet
test_pkt = Ether()/IP(src="192.168.1.1", dst="192.168.1.2")/TCP(sport=12345, dport=443)

# Parse it
result = parse_packet(test_pkt)
print(result)
# Expected: {'source_ip': '192.168.1.1', 'dest_ip': '192.168.1.2', 'protocol': 'HTTPS', ...}
```

### Test on Your Machine

1. Start capture
2. Open a web browser
3. Navigate to any website
4. Watch packets appear in your logs

---

## Coordination with Team

### With Member 5 (Database)
- **Agree on packet data format:**
  ```python
  {
      'timestamp': datetime,
      'source_ip': str,
      'dest_ip': str,
      'source_port': int or None,
      'dest_port': int or None,
      'protocol': str,
      'bytes': int
  }
  ```
- **Test save_packet() function** before full integration

### With Member 1 (Project Lead)
- **Provide NetworkMonitor class** with start() and stop() methods
- **Report any config values needed** (interface name, etc.)
- **Report permission requirements** for documentation
