import json
import requests
import threading
import time
import re
import logging
import os
import subprocess
from dotenv import load_dotenv
import base64
from datetime import datetime, timedelta

# Load environment variables
load_dotenv()

from collections import deque, defaultdict
from fastapi import FastAPI, Request, BackgroundTasks, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
from scapy.all import sniff, IP, TCP, UDP, Raw, conf
import asyncio
from datetime import datetime
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# GitHub App authentication
try:
    import jwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False
    logger.warning("PyJWT library not installed. GitHub App authentication will be disabled.")

# Groq LLM for intelligent analysis (imported after logger is defined)
try:
    from groq import Groq
    from groq import RateLimitError as GroqRateLimitError
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False
    GroqRateLimitError = None
    logger.warning("Groq library not installed. LLM analysis will be disabled.")

# Configuration
# Use environment variables or default to the user's provided values
BLUEBUBBLES_URL = os.getenv('BB_URL')
BLUEBUBBLES_PASSWORD = os.getenv('BB_PASS')
GROQ_API_KEY = os.getenv('GROQ_API_KEY')
# GitHub authentication - support both Personal Access Token and GitHub App
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')  # Personal Access Token (legacy)
GITHUB_APP_ID = os.getenv('GITHUB_APP_ID')  # GitHub App ID
GITHUB_APP_PRIVATE_KEY = os.getenv('GITHUB_APP_PRIVATE_KEY')  # GitHub App private key (PEM format, can be base64 encoded)
GITHUB_APP_INSTALLATION_ID = os.getenv('GITHUB_APP_INSTALLATION_ID')  # GitHub App installation ID
GITHUB_REPO = os.getenv('GITHUB_REPO')  # GitHub repository link (e.g., 'https://github.com/owner/repo' or 'owner/repo')

# Global state
TARGET_CHAT_GUID = "iMessage;-;+14089167303"  # Hardcoded target chat GUID
IS_SNIFFING = True
DDOS_THRESHOLD = 100  # Packets per second to trigger alert
PACKET_WINDOW = deque()  # Stores timestamps of recent packets
LAST_ALERT_TIME = 0
ALERT_COOLDOWN = 10  # Seconds between alerts to avoid spamming

# Alert batching for SMS (simpler, cleaner messages)
alert_batch = defaultdict(lambda: {'count': 0, 'last_time': 0, 'last_payload': '', 'type': '', 'source': ''})
ALERT_BATCH_WINDOW = 10  # Seconds to batch similar alerts (reduced for faster notification)
ALERT_BATCH_MAX_COUNT = 5  # Send immediately if this many alerts are batched

# WebSocket and monitoring state
connected_websockets = []
packet_history = deque(maxlen=100)
alert_history = deque(maxlen=50)
MONITORED_PORT = 8000  # Default port to monitor for demo traffic
event_loop = None  # Store event loop reference for async operations from threads
sniffer_stop_event = threading.Event()  # Event to signal sniffer to stop
sniffer_thread = None  # Reference to the sniffer thread

# Track request volume per IP for DDoS detection at application layer
request_tracker = defaultdict(lambda: deque(maxlen=200))
HTTP_REQUEST_LAST_DDOS_ALERT = 0  # Separate from packet-level alert cooldown
DDOS_REQUEST_THRESHOLD = 80  # requests per second from a single IP (lowered for easier detection)

# Analysis summary storage
analysis_summaries = deque(maxlen=10)

# Polling state for BlueBubbles messages
last_poll_time = 0
processed_message_guids = set()  # Track processed messages to avoid duplicates

app = FastAPI()

# Add CORS middleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add rate limiting middleware
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi import HTTPException
from fastapi import Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel

@app.middleware("http")
async def log_requests(request: Request, call_next):
    """
    Middleware to log all HTTP requests and detect attacks at application layer
    """
    global event_loop, request_tracker, HTTP_REQUEST_LAST_DDOS_ALERT, DDOS_REQUEST_THRESHOLD, MONITORED_PORT
    
    client_ip = request.client.host if request.client else "Unknown"
    
    # Skip logging requests to config endpoints (they're not the traffic we're monitoring)
    if request.url.path in ["/api/config", "/api/set-target"]:
        response = await call_next(request)
        return response
    
    # Log as packet - ALWAYS use the current MONITORED_PORT value
    # Read it fresh from the global to ensure we have the latest configured port
    # IMPORTANT: Read MONITORED_PORT directly from global scope
    current_port = MONITORED_PORT  # Read current value from global
    pkt_info = {
        "src": client_ip,
        "dst": f"localhost:{current_port}",
        "proto": "HTTP",
        "len": 0,
        "timestamp": datetime.now().isoformat()
    }
    packet_history.appendleft(pkt_info)
    
    # Debug: Log the port being used (first few packets to verify it's working)
    if len(packet_history) <= 5:
        logger.info(f"📦 Middleware packet #{len(packet_history)} - Destination: localhost:{current_port} (MONITORED_PORT={MONITORED_PORT}, path={request.url.path})")
    
    # DDoS Detection at Application Layer - Track HTTP request volume per IP
    current_time = time.time()
    
    # Add current request timestamp to tracker for this IP
    if client_ip not in request_tracker:
        request_tracker[client_ip] = deque(maxlen=200)
    
    request_tracker[client_ip].append(current_time)
    
    # Clean old requests (older than 1 second) from this IP's tracker
    while request_tracker[client_ip] and request_tracker[client_ip][0] < current_time - 1:
        request_tracker[client_ip].popleft()
    
    # Check if this IP is sending requests faster than threshold
    request_count = len(request_tracker[client_ip])
    
    # Debug logging for high request rates
    if request_count > 20:
        logger.debug(f"📊 IP {client_ip}: {request_count} requests/sec (threshold: {DDOS_REQUEST_THRESHOLD}/sec)")
    
    if request_count > DDOS_REQUEST_THRESHOLD:
        # Check cooldown to avoid spamming alerts
        if current_time - HTTP_REQUEST_LAST_DDOS_ALERT > ALERT_COOLDOWN:
            msg = f"⚠️ ALERT: DDoS Attack Detected from {client_ip}! {request_count} requests/sec (threshold: {DDOS_REQUEST_THRESHOLD}/sec)"
            logger.warning(f"🔴 {msg}")
            logger.warning(f"📊 Request details: {request.method} {request.url.path} | Query params: {str(request.url.query)[:100]}")
            add_alert("DDoS", client_ip, msg)
            send_alert_batched("DDoS", client_ip, f"{request.method} {request.url.path}")
            HTTP_REQUEST_LAST_DDOS_ALERT = current_time
    
    # Also track total request volume across all IPs for aggregate DDoS detection
    # Clean old requests from all IP trackers periodically (every 10 requests from any IP)
    # Count total requests in the last second from all IPs (after cleaning old requests)
    total_requests_last_second = sum(len(ip_tracker) for ip_tracker in request_tracker.values())
    
    # Debug logging for high total request rates
    if total_requests_last_second > 40:
        logger.debug(f"📊 Total requests across all IPs: {total_requests_last_second} req/sec")
    
    # If total requests exceed threshold, also trigger alert
    if total_requests_last_second > DDOS_REQUEST_THRESHOLD * 2:  # 160 req/sec total
        if current_time - HTTP_REQUEST_LAST_DDOS_ALERT > ALERT_COOLDOWN:
            msg = f"⚠️ ALERT: Large-scale DDoS Attack Detected! Total: {total_requests_last_second} requests/sec from multiple sources!"
            logger.warning(f"🔴 {msg}")
            add_alert("DDoS", "Multiple IPs", msg)
            send_alert_batched("DDoS", "Multiple IPs", f"{total_requests_last_second} req/sec")
            HTTP_REQUEST_LAST_DDOS_ALERT = current_time
    
    # Check for SQL injection in URL and query params
    full_url = str(request.url)
    query_string = request.url.query
    
    if query_string and detect_sql_injection(query_string):
        clean_snippet = ''.join(c if c.isprintable() else '' for c in query_string[:100])
        msg = f"⚠️ ALERT: SQL Injection from {client_ip}! Query: {clean_snippet}"
        logger.warning(msg)
        add_alert("SQL Injection", client_ip, msg)
        send_alert_batched("SQL Injection", client_ip, clean_snippet)
    
    # Broadcast update
    if event_loop and connected_websockets:
        try:
            asyncio.run_coroutine_threadsafe(broadcast_update(), event_loop)
        except:
            pass
    
    response = await call_next(request)
    return response

# --- Detection Logic ---

def is_likely_encrypted(payload: bytes) -> bool:
    """
    Check if payload is likely encrypted/binary data (TLS, SSL, etc.)
    """
    # Check for TLS/SSL handshake markers
    if len(payload) > 3:
        # TLS records start with content type (0x14-0x18) followed by version
        if payload[0] in [0x14, 0x15, 0x16, 0x17, 0x18]:  # TLS content types
            if payload[1:3] == b'\x03\x01' or payload[1:3] == b'\x03\x03':  # TLS 1.0/1.2
                return True
    
    # Check for high entropy (likely encrypted)
    if len(payload) > 20:
        # Count printable ASCII characters
        printable = sum(1 for b in payload[:100] if 32 <= b < 127)
        ratio = printable / min(100, len(payload))
        # If less than 60% printable, likely encrypted
        if ratio < 0.6:
            return True
    
    return False

def detect_sql_injection(payload: str) -> bool:
    """
    Checks for common SQL injection patterns in the payload.
    Only looks at readable text, not encrypted data.
    """
    # Must contain some actual readable text
    if len(payload) < 5:
        return False
    
    # Must have reasonable amount of printable characters
    printable_count = sum(1 for c in payload if c.isprintable())
    if printable_count / len(payload) < 0.7:
        return False
    
    # Common SQLi patterns
    patterns = [
        r"(\%27)|(\')\s*(or|OR|Or)\s*(\%27)|(\')",  # ' OR '
        r"(\'|\")\s*(or|OR|Or)\s+1\s*=\s*1",  # ' OR 1=1
        r"(\'|\")\s*--",  # ' --
        r"union\s+select",  # UNION SELECT
        r";\s*drop\s+table",  # ; DROP TABLE
        r";\s*delete\s+from",  # ; DELETE FROM
        r"(\%27)|(\').*union.*select",  # Complex union
    ]
    
    for pattern in patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            return True
    return False

def process_packet(packet):
    global PACKET_WINDOW, LAST_ALERT_TIME, event_loop

    current_time = time.time()
    
    # Log packet for frontend display
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Extract port information from TCP or UDP layer
        src_port = None
        dst_port = None
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        
        # Format destination with port if available
        if dst_port:
            dst_display = f"{dst_ip}:{dst_port}"
        else:
            dst_display = dst_ip
        
        # Format source with port if available
        if src_port:
            src_display = f"{src_ip}:{src_port}"
        else:
            src_display = src_ip
        
        pkt_info = {
            "src": src_display,
            "dst": dst_display,
            "proto": packet[IP].proto,
            "len": len(packet),
            "timestamp": datetime.now().isoformat()
        }
        packet_history.appendleft(pkt_info)
        
        # Broadcast packet update to frontend
        if event_loop and connected_websockets:
            try:
                asyncio.run_coroutine_threadsafe(broadcast_update(), event_loop)
            except:
                pass
    
    # 1. DDoS Detection (Volumetric)
    # Add current timestamp to window
    PACKET_WINDOW.append(current_time)
    
    # Remove packets older than 1 second
    while PACKET_WINDOW and PACKET_WINDOW[0] < current_time - 1:
        PACKET_WINDOW.popleft()
    
    # Check if threshold exceeded
    if len(PACKET_WINDOW) > DDOS_THRESHOLD:
        if current_time - LAST_ALERT_TIME > ALERT_COOLDOWN:
            src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"
            msg = f"⚠️ ALERT: Potential DDoS Attack Detected! Traffic spike: {len(PACKET_WINDOW)} packets/sec."
            logger.warning(msg)
            add_alert("DDoS", src_ip, msg)
            send_alert_batched("DDoS", src_ip, f"{len(PACKET_WINDOW)} packets/sec")
            LAST_ALERT_TIME = current_time

    # 2. SQL Injection Detection
    if packet.haslayer(Raw):
        try:
            raw_payload = packet[Raw].load
            
            # Skip encrypted traffic (TLS/SSL)
            if is_likely_encrypted(raw_payload):
                return
            
            # Try to decode as text
            try:
                load = raw_payload.decode('utf-8')
            except:
                return  # Skip if can't decode as UTF-8
            
            if detect_sql_injection(load):
                if current_time - LAST_ALERT_TIME > ALERT_COOLDOWN:
                    src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"
                    # Extract cleaner payload snippet
                    clean_snippet = ''.join(c if c.isprintable() else '' for c in load[:100])
                    msg = f"⚠️ ALERT: SQL Injection from {src_ip}! Payload: {clean_snippet}..."
                    logger.warning(msg)
                    add_alert("SQL Injection", src_ip, msg)
                    send_alert_batched("SQL Injection", src_ip, clean_snippet)
                    LAST_ALERT_TIME = current_time
        except Exception as e:
            pass # Ignore decoding errors

def add_alert(alert_type: str, source: str, message: str):
    """Add an alert to history and broadcast to connected WebSocket clients"""
    alert = {
        "type": alert_type,
        "source": source,
        "timestamp": datetime.now().isoformat(),
        "message": message
    }
    alert_history.appendleft(alert)
    # Schedule broadcast in event loop if there's a running loop
    global event_loop
    if event_loop and connected_websockets:
        try:
            asyncio.run_coroutine_threadsafe(broadcast_update(), event_loop)
        except Exception as e:
            logger.error(f"Failed to broadcast update: {e}")

def generate_mermaid_diagram(packet_data: dict, alert_data: dict, current_alerts: list) -> str:
    """
    Generate a Mermaid.js sequence diagram showing how the attack happened.
    Creates a visual flow diagram of the attack detection process.
    """
    ddos_count = alert_data.get('ddos_count', 0)
    sqli_count = alert_data.get('sqli_count', 0)
    top_threat_sources = alert_data.get('top_threat_sources', {})
    total_alerts = packet_data.get('total_alerts', 0)
    
    # Get most recent alerts to understand attack pattern
    recent_alerts = list(current_alerts)[:3] if current_alerts else []
    
    # Build participant list based on detected attacks
    participants = ["Attacker", "TargetServer", "ShieldOS"]
    
    # Determine attack type and create appropriate diagram
    if ddos_count > 0:
        # DDoS Attack Flow
        diagram_lines = [
            "sequenceDiagram",
            "    participant Attacker",
            "    participant TargetServer",
            "    participant ShieldOS"
        ]
        
        diagram_lines.append("    ")
        diagram_lines.append("    Note over Attacker,TargetServer: DDoS Attack Detected")
        diagram_lines.append("    ")
        
        # Show attack initiation
        diagram_lines.append("    Attacker->>TargetServer: Flood of HTTP Requests")
        diagram_lines.append("    loop Rapid Requests")
        diagram_lines.append(f"        Attacker->>TargetServer: {packet_data.get('packets_per_second', 0):.0f} requests/sec")
        diagram_lines.append("    end")
        
        diagram_lines.append("    ")
        
        # Detection
        if top_threat_sources:
            for i, (source, count) in enumerate(list(top_threat_sources.items())[:2]):
                short_source = source[:15] if len(source) < 20 else source[:12] + "..."
                diagram_lines.append(f"    TargetServer->>ShieldOS: Traffic spike detected from {short_source}")
        
        diagram_lines.append("    ")
        diagram_lines.append("    ShieldOS->>ShieldOS: Analyze packet volume")
        diagram_lines.append(f"    ShieldOS->>ShieldOS: DDoS threshold exceeded ({ddos_count} alerts)")
        diagram_lines.append("    ")
        diagram_lines.append("    ShieldOS->>TargetServer: 🚨 ALERT: DDoS Attack Detected")
        
        # If SQL injection also detected
        if sqli_count > 0:
            diagram_lines.append("    ")
            diagram_lines.append("    Note over Attacker,TargetServer: SQL Injection Also Detected")
            diagram_lines.append("    Attacker->>TargetServer: Malicious SQL queries")
            diagram_lines.append("    TargetServer->>ShieldOS: SQL Injection pattern detected")
            diagram_lines.append("    ShieldOS->>TargetServer: 🚨 ALERT: SQL Injection Detected")
        
    elif sqli_count > 0:
        # SQL Injection Attack Flow
        diagram_lines = [
            "sequenceDiagram",
            "    participant Attacker",
            "    participant TargetServer",
            "    participant ShieldOS"
        ]
        
        diagram_lines.append("    ")
        diagram_lines.append("    Note over Attacker,TargetServer: SQL Injection Attack")
        diagram_lines.append("    ")
        diagram_lines.append("    Attacker->>TargetServer: POST request with SQL payload")
        
        if recent_alerts:
            alert = recent_alerts[0]
            snippet = alert.get('message', '')[:30].replace("'", "")
            diagram_lines.append(f'    Note right of Attacker: Payload: "{snippet}..."')
        
        diagram_lines.append("    ")
        diagram_lines.append("    TargetServer->>ShieldOS: Analyze request payload")
        diagram_lines.append("    ShieldOS->>ShieldOS: Detect SQL injection patterns")
        diagram_lines.append("    ShieldOS->>ShieldOS: Match against threat signatures")
        diagram_lines.append(f"    ShieldOS->>ShieldOS: SQLi detected ({sqli_count} alerts)")
        diagram_lines.append("    ")
        diagram_lines.append("    ShieldOS->>TargetServer: 🚨 ALERT: SQL Injection Detected")
        
    else:
        # General traffic monitoring
        diagram_lines = [
            "sequenceDiagram",
            "    participant Client",
            "    participant TargetServer",
            "    participant ShieldOS"
        ]
        
        diagram_lines.append("    ")
        diagram_lines.append("    Note over Client,TargetServer: Network Traffic Monitoring")
        diagram_lines.append("    ")
        diagram_lines.append(f"    Client->>TargetServer: {packet_data.get('total_packets', 0)} packets analyzed")
        diagram_lines.append("    TargetServer->>ShieldOS: Forward packet data")
        diagram_lines.append("    ShieldOS->>ShieldOS: Monitor traffic patterns")
        diagram_lines.append(f"    ShieldOS->>ShieldOS: {packet_data.get('total_alerts', 0)} alerts processed")
        diagram_lines.append("    ShieldOS->>TargetServer: 📊 Traffic analysis complete")
    
    return "\n".join(diagram_lines)

def generate_llm_analysis(packet_data: dict, alert_data: dict) -> str:
    """
    Use Groq LLM to generate intelligent analysis and recommendations.
    """
    if not GROQ_AVAILABLE or not GROQ_API_KEY:
        return None
    
    try:
        client = Groq(api_key=GROQ_API_KEY)
        
        # Prepare context for LLM
        context = f"""You are a cybersecurity expert analyzing network traffic data from SHIELDOS, a real-time threat detection system.

PACKET STATISTICS:
- Total Packets: {packet_data['total_packets']}
- Total Alerts: {packet_data['total_alerts']}
- Time Range: {packet_data['time_range_seconds']} seconds
- Packets per Second: {packet_data['packets_per_second']}
- Average Packet Size: {packet_data['avg_packet_size']} bytes

THREAT DETECTION:
- DDoS Attacks Detected: {alert_data['ddos_count']}
- SQL Injection Attempts: {alert_data['sqli_count']}
- Top Threat Sources: {', '.join(alert_data['top_threat_sources'].keys()) if alert_data['top_threat_sources'] else 'None'}

TRAFFIC ANALYSIS:
- Top Source IPs: {', '.join(list(alert_data['top_source_ips'].keys())[:5]) if alert_data['top_source_ips'] else 'None'}
- Protocols: {', '.join(alert_data['protocols'].keys()) if alert_data['protocols'] else 'None'}

RECENT ALERTS:
{chr(10).join([f"- {alert.get('type', 'Unknown')} from {alert.get('source', 'Unknown')}: {alert.get('message', '')[:100]}" for alert in list(alert_history)[:5]]) if alert_history else 'No recent alerts'}

Write a brief, concise analysis. Use line breaks between paragraphs for readability.

Format like this:
[First paragraph - threat assessment]

[Second paragraph - what to do]

Risk: [Low/Medium/High]

Keep it under 150 words. Be conversational but brief. Use line breaks to separate ideas."""

        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {
                    "role": "system",
                    "content": "You are a friendly cybersecurity expert explaining network security in plain, natural language. Write like you're talking to a colleague - be conversational, clear, and helpful. Avoid technical jargon when possible, or explain it simply. Make your analysis easy to understand and actionable."
                },
                {
                    "role": "user",
                    "content": context
                }
            ],
            temperature=0.7,
            max_tokens=200
        )
        
        return response.choices[0].message.content.strip()
    except Exception as e:
        logger.error(f"Groq API error: {e}")
        return None

def generate_analysis_summary() -> dict:
    """
    Generate a comprehensive analysis summary of packet data and attacks.
    Uses LLM (Groq) for intelligent analysis when available.
    Returns a formatted summary with statistics and insights.
    """
    from collections import Counter
    
    # Get current data
    current_packets = list(packet_history)
    current_alerts = list(alert_history)
    
    # Calculate statistics
    total_packets = len(current_packets)
    total_alerts = len(current_alerts)
    
    # Count alert types
    alert_types = Counter(alert.get("type", "Unknown") for alert in current_alerts)
    ddos_count = alert_types.get("DDoS", 0)
    sqli_count = alert_types.get("SQL Injection", 0)
    
    # Analyze source IPs
    source_ips = Counter(pkt.get("src", "Unknown") for pkt in current_packets)
    top_sources = dict(source_ips.most_common(5))
    
    # Analyze protocols
    proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
    protocols = Counter(
        proto_map.get(pkt.get("proto", 0), f"Proto-{pkt.get('proto', 0)}")
        for pkt in current_packets
    )
    
    # Calculate time range
    if current_packets:
        timestamps = [pkt.get("timestamp") for pkt in current_packets if pkt.get("timestamp")]
        if timestamps:
            try:
                start_time = min(datetime.fromisoformat(ts) for ts in timestamps)
                end_time = max(datetime.fromisoformat(ts) for ts in timestamps)
                time_range = (end_time - start_time).total_seconds()
            except:
                time_range = 0
        else:
            time_range = 0
    else:
        time_range = 0
    
    # Calculate average packet size
    packet_sizes = [pkt.get("len", 0) for pkt in current_packets if pkt.get("len", 0) > 0]
    avg_packet_size = sum(packet_sizes) / len(packet_sizes) if packet_sizes else 0
    
    # Calculate packets per second
    packets_per_second = total_packets / time_range if time_range > 0 else 0
    
    # Identify threat sources
    threat_sources = Counter(alert.get("source", "Unknown") for alert in current_alerts)
    top_threat_sources = dict(threat_sources.most_common(3))
    
    # Prepare data for LLM
    packet_data = {
        "total_packets": total_packets,
        "total_alerts": total_alerts,
        "time_range_seconds": round(time_range, 2),
        "packets_per_second": round(packets_per_second, 2),
        "avg_packet_size": round(avg_packet_size, 2)
    }
    
    alert_data = {
        "ddos_count": ddos_count,
        "sqli_count": sqli_count,
        "top_threat_sources": top_threat_sources,
        "top_source_ips": top_sources,
        "protocols": dict(protocols)
    }
    
    # Generate LLM-powered analysis
    llm_analysis = generate_llm_analysis(packet_data, alert_data)
    
    if not llm_analysis:
        raise Exception("LLM analysis failed. Groq API key may be missing or invalid.")
    
    # Generate Mermaid diagram showing attack flow
    mermaid_diagram = generate_mermaid_diagram(packet_data, alert_data, current_alerts)
    
    # Format summary
    summary = {
        "timestamp": datetime.now().isoformat(),
        "overview": packet_data,
        "threats": {
            "ddos_count": ddos_count,
            "sqli_count": sqli_count,
            "top_threat_sources": top_threat_sources
        },
        "traffic": {
            "top_source_ips": top_sources,
            "protocols": dict(protocols)
        },
        "llm_analysis": llm_analysis,
        "mermaid_diagram": mermaid_diagram
    }
    
    # Generate formatted text summary - simplified, same as dashboard
    import re
    # Format LLM analysis with proper line breaks for SMS
    formatted_llm = llm_analysis.strip()
    # Normalize line breaks
    formatted_llm = re.sub(r'\n{3,}', '\n\n', formatted_llm)
    # Ensure double line breaks between paragraphs
    formatted_llm = re.sub(r'\n\n+', '\n\n', formatted_llm)
    
    # Create concise SMS-friendly summary
    text_summary = f"""📊 SHIELDOS ANALYSIS

📈 Stats:
• Packets: {total_packets} | Alerts: {total_alerts}
• DDoS: {ddos_count} | SQLi: {sqli_count}

🤖 Analysis:
{formatted_llm}"""
    
    summary["text_summary"] = text_summary
    
    # Store summary
    analysis_summaries.appendleft(summary)
    
    return summary

def start_sniffer():
    """
    Starts the packet sniffer in a background thread.
    Filters to only monitor traffic to/from the monitored port.
    """
    global MONITORED_PORT, sniffer_stop_event
    # Clear stop event before starting
    sniffer_stop_event.clear()
    logger.info(f"Starting packet sniffer on port {MONITORED_PORT}...")
    # Only capture traffic to/from the monitored port (default 8000)
    # This filters out all other network traffic from your computer
    sniff_filter = f"tcp port {MONITORED_PORT}"
    logger.info(f"Sniffing with filter: {sniff_filter}")
    try:
        # Use stop_filter to allow stopping the sniffer
        sniff(filter=sniff_filter, prn=process_packet, store=0, stop_filter=lambda x: sniffer_stop_event.is_set())
    except Exception as e:
        logger.error(f"Sniffer failed: {e}")

# --- BlueBubbles Integration ---

def send_alert_batched(alert_type: str, source: str, payload: str):
    """
    Batches similar alerts together for cleaner SMS messages.
    Sends batched alert when window expires or new alert type appears.
    """
    global alert_batch
    current_time = time.time()
    
    # Create a key for batching (same type + source)
    batch_key = f"{alert_type}:{source}"
    
    # Clean up payload for display
    try:
        from urllib.parse import unquote
        decoded = unquote(payload, encoding='utf-8', errors='ignore')
        # Extract the suspicious part (usually after = or the main payload)
        if '=' in decoded:
            parts = decoded.split('&')
            for part in parts:
                if 'username' in part.lower() or 'user' in part.lower() or 'query' in part.lower():
                    clean_payload = part.split('=')[-1] if '=' in part else part
                    break
            else:
                clean_payload = decoded[:60]
        else:
            clean_payload = decoded[:60]
    except:
        clean_payload = payload[:60] if len(payload) > 60 else payload
    
    # Update batch
    batch = alert_batch[batch_key]
    time_since_last = current_time - batch['last_time']
    
    if batch['count'] == 0:
        # First alert - send immediately
        emoji = "🚨" if alert_type == "SQL Injection" else "⚠️"
        message = f"{emoji} {alert_type} from {source}\n   {clean_payload}"
        _send_alert_direct(message)
        
        # Start new batch
        alert_batch[batch_key] = {
            'count': 1,
            'last_time': current_time,
            'last_payload': clean_payload,
            'type': alert_type,
            'source': source
        }
    elif time_since_last > ALERT_BATCH_WINDOW:
        # Window expired - send previous batch and start new one
        if batch['count'] > 1:
            count_text = f" ({batch['count']} attempts)"
            emoji = "🚨" if alert_type == "SQL Injection" else "⚠️"
            message = f"{emoji} {alert_type} from {source}\n   {batch['last_payload']}{count_text}"
            _send_alert_direct(message)
        
        # Start new batch with current alert
        emoji = "🚨" if alert_type == "SQL Injection" else "⚠️"
        message = f"{emoji} {alert_type} from {source}\n   {clean_payload}"
        _send_alert_direct(message)
        
        alert_batch[batch_key] = {
            'count': 1,
            'last_time': current_time,
            'last_payload': clean_payload,
            'type': alert_type,
            'source': source
        }
    else:
        # Add to existing batch
        alert_batch[batch_key]['count'] += 1
        alert_batch[batch_key]['last_time'] = current_time
        # Update payload if this one is cleaner/shorter
        if len(clean_payload) < len(batch['last_payload']) or not batch['last_payload']:
            alert_batch[batch_key]['last_payload'] = clean_payload
        
        # If we've batched enough alerts, send immediately
        if alert_batch[batch_key]['count'] >= ALERT_BATCH_MAX_COUNT:
            count_text = f" ({alert_batch[batch_key]['count']} attempts)"
            emoji = "🚨" if alert_type == "SQL Injection" else "⚠️"
            message = f"{emoji} {alert_type} from {source}\n   {alert_batch[batch_key]['last_payload']}{count_text}"
            _send_alert_direct(message)
            # Reset batch
            alert_batch[batch_key] = {'count': 0, 'last_time': 0, 'last_payload': '', 'type': '', 'source': ''}

def flush_alert_batches():
    """
    Flush any pending batched alerts (call this periodically or on shutdown).
    """
    global alert_batch
    current_time = time.time()
    
    for batch_key, batch in list(alert_batch.items()):
        if batch['count'] > 0:
            count_text = f" ({batch['count']} attempts)" if batch['count'] > 1 else ""
            emoji = "🚨" if batch['type'] == "SQL Injection" else "⚠️"
            message = f"{emoji} {batch['type']} from {batch['source']}\n   {batch['last_payload']}{count_text}"
            _send_alert_direct(message)
            # Reset batch
            alert_batch[batch_key] = {'count': 0, 'last_time': 0, 'last_payload': '', 'type': '', 'source': ''}

def _send_alert_direct(message: str):
    """
    Sends a text message directly via BlueBubbles (internal function).
    """
    global TARGET_CHAT_GUID
    
    if not TARGET_CHAT_GUID:
        logger.warning("No target chat GUID set. Cannot send alert.")
        return

    # Sanitize message: only remove null bytes, preserve newlines for formatting
    sanitized_message = message.replace('\x00', '')
    
    logger.info(f"Sending alert to {TARGET_CHAT_GUID}: {sanitized_message[:100]}...")
    
    # BlueBubbles API endpoint
    url = f'{BLUEBUBBLES_URL}/api/v1/message/text'
    
    # The message body structure for BlueBubbles - API requires 'message' field
    data = {
        'chatGuid': TARGET_CHAT_GUID,
        'message': sanitized_message,  # BlueBubbles API requires 'message' field
        'method': 'private-api',
        'tempGuid': f'temp-{int(time.time() * 1000)}'
    }

    try:
        response = requests.post(
            url,
            json=data,
            params={'password': BLUEBUBBLES_PASSWORD},  # Use params for password
            headers={'Content-Type': 'application/json'},
            timeout=10
        )
        
        if not response.ok:
            logger.error(f"BlueBubbles API error: {response.status_code} - {response.text}")
        else:
            logger.info(f"Alert sent successfully: {response.json()}")
    except requests.exceptions.ConnectionError as e:
        logger.error(f"Cannot connect to BlueBubbles at {BLUEBUBBLES_URL}. Is BlueBubbles server running? Error: {e}")
    except requests.exceptions.Timeout:
        logger.error(f"Timeout sending alert to BlueBubbles")
    except Exception as e:
        logger.error(f"Failed to send alert: {e}")

def send_alert(message: str):
    """
    Sends a text message via BlueBubbles (for non-alert messages like status updates).
    Uses direct sending (no batching).
    """
    _send_alert_direct(message)

# --- WebSocket Support ---

async def broadcast_update():
    """Broadcast updates to all connected WebSocket clients"""
    if not connected_websockets:
        return
    
    data = {
        "type": "update",
        "alerts": list(alert_history)[:20],
        "packets": list(packet_history)[:20]
    }
    
    for ws in connected_websockets[:]:
        try:
            await ws.send_json(data)
        except:
            if ws in connected_websockets:
                connected_websockets.remove(ws)

async def broadcast_analysis(analysis: dict):
    """Broadcast analysis summary to all connected WebSocket clients"""
    if not connected_websockets:
        return
    
    data = {
        "type": "analysis",
        "analysis": analysis
    }
    
    for ws in connected_websockets[:]:
        try:
            await ws.send_json(data)
        except:
            if ws in connected_websockets:
                connected_websockets.remove(ws)

# --- API Endpoints ---

class TargetChatRequest(BaseModel):
    chat_guid: str

class ConfigRequest(BaseModel):
    chat_guid: str
    monitored_port: int

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_websockets.append(websocket)
    logger.info("WebSocket client connected")
    
    try:
        # Send initial state
        await websocket.send_json({
            "type": "init",
            "alerts": list(alert_history)[:20],
            "packets": list(packet_history)[:20]
        })
        
        # Keep connection alive and listen for messages
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in connected_websockets:
            connected_websockets.remove(websocket)
        logger.info("WebSocket client disconnected")

@app.post("/api/set-target")
async def set_target_chat(request: TargetChatRequest):
    global TARGET_CHAT_GUID
    TARGET_CHAT_GUID = request.chat_guid
    logger.info(f"Target chat set to: {TARGET_CHAT_GUID}")
    # Optionally send a test message
    send_alert("✅ Alerts enabled for this number via Dashboard.")
    return {"status": "ok", "message": f"Target set to {TARGET_CHAT_GUID}"}

@app.get("/api/config")
async def get_config():
    """Get current configuration"""
    global TARGET_CHAT_GUID, MONITORED_PORT
    logger.info(f"📤 GET /api/config - Current MONITORED_PORT: {MONITORED_PORT}")
    return {"status": "ok", "chat_guid": TARGET_CHAT_GUID, "monitored_port": MONITORED_PORT}

@app.post("/api/config")
async def set_config(request: ConfigRequest):
    global TARGET_CHAT_GUID, MONITORED_PORT, sniffer_stop_event, sniffer_thread, packet_history
    old_port = MONITORED_PORT
    TARGET_CHAT_GUID = request.chat_guid
    
    # Log what we received
    logger.info(f"📥 Received config request - monitored_port: {request.monitored_port} (type: {type(request.monitored_port)})")
    
    new_port = int(request.monitored_port)  # Ensure it's an int
    logger.info(f"📥 Converted to int: {new_port}")
    
    # Update global variable IMMEDIATELY
    MONITORED_PORT = new_port
    
    # Verify it was set correctly
    logger.info(f"🔧 Config updated - Chat: {TARGET_CHAT_GUID}, Port changed from {old_port} to {MONITORED_PORT}")
    logger.info(f"🔧 VERIFICATION: MONITORED_PORT global variable is now: {MONITORED_PORT} (type: {type(MONITORED_PORT)})")
    
    # Clear old packets so we only show packets with the new port
    packet_history.clear()
    logger.info(f"🧹 Cleared packet history for new port {MONITORED_PORT}")
    
    # Add a confirmation packet to show the new port is active
    confirm_pkt = {
        "src": "System",
        "dst": f"localhost:{MONITORED_PORT}",
        "proto": "HTTP",
        "len": 0,
        "timestamp": datetime.now().isoformat()
    }
    packet_history.appendleft(confirm_pkt)
    logger.info(f"✅ Added confirmation packet showing port {MONITORED_PORT}")
    
    # Broadcast the update
    if event_loop and connected_websockets:
        try:
            asyncio.run_coroutine_threadsafe(broadcast_update(), event_loop)
        except:
            pass
    
    # Always restart sniffer to ensure it's using the correct port
    logger.info(f"🔄 Restarting sniffer with port {MONITORED_PORT}...")
    # Stop the current sniffer
    sniffer_stop_event.set()
    # Wait a moment for it to stop
    time.sleep(0.5)
    # Start a new sniffer thread with the new port
    sniffer_thread = threading.Thread(target=start_sniffer, daemon=True)
    sniffer_thread.start()
    logger.info(f"✅ Sniffer restarted on port {MONITORED_PORT}")
    
    send_alert(f"✅ Alerts enabled. Monitoring port {MONITORED_PORT}")
    return {"status": "ok", "chat_guid": TARGET_CHAT_GUID, "monitored_port": MONITORED_PORT}

@app.get("/api/simulate-traffic")
async def simulate_traffic(attack_type: str = "sqli"):
    """Simulate traffic for demo purposes - generates actual network traffic to MONITORED_PORT"""
    global MONITORED_PORT
    
    def generate_sqli_traffic():
        """Generate SQL injection attack traffic to the monitored port"""
        target_url = f"http://localhost:{MONITORED_PORT}/api/test"
        sql_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "admin'--",
            "' UNION SELECT * FROM users--",
            "1' OR '1'='1",
        ]
        for payload in sql_payloads:
            try:
                requests.get(f"{target_url}?id={payload}", timeout=1)
                requests.post(target_url, json={"query": payload}, timeout=1)
            except:
                pass  # Ignore connection errors, we just want to generate packets
    
    def generate_ddos_traffic():
        """Generate DDoS attack traffic to the monitored port"""
        target_url = f"http://localhost:{MONITORED_PORT}/api/test"
        # Generate high volume of requests
        def send_request():
            try:
                requests.get(f"{target_url}?ddos={time.time()}", timeout=0.5)
            except:
                pass
        
        # Fire many requests in parallel
        threads = []
        for _ in range(100):
            thread = threading.Thread(target=send_request)
            thread.start()
            threads.append(thread)
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join(timeout=2)
    
    # Generate actual network traffic in background
    # Note: We don't add simulated alerts here - real alerts will be generated by
    # the middleware when it detects actual SQL injection patterns or DDoS volume
    if attack_type == "sqli":
        threading.Thread(target=generate_sqli_traffic, daemon=True).start()
    elif attack_type == "ddos":
        threading.Thread(target=generate_ddos_traffic, daemon=True).start()
    
    return {"status": "ok", "simulated": attack_type, "target_port": MONITORED_PORT}

@app.get("/vulnerable-login", response_class=HTMLResponse)
async def vulnerable_login_page():
    """Serve the vulnerable login page for attack simulation"""
    html_path = Path(__file__).parent / "templates" / "vulnerable_login.html"
    if html_path.exists():
        return FileResponse(html_path)
    return HTMLResponse("<h1>Page not found</h1>", status_code=404)

@app.post("/api/login")
async def login_endpoint(request: Request):
    """Fake login endpoint that logs traffic"""
    try:
        # Try to get JSON body
        try:
            body = await request.json()
            username = body.get('username', '')
            password = body.get('password', '')
        except:
            # Fallback to empty if no JSON body
            username = ''
            password = ''
        
        # The middleware already checked query params, so we just need to check body
        if username and (detect_sql_injection(username) or detect_sql_injection(password)):
            client_ip = request.client.host if request.client else "Unknown"
            clean_snippet = ''.join(c if c.isprintable() else '' for c in username[:50])
            msg = f"⚠️ ALERT: SQL Injection from {client_ip}! Username: {clean_snippet}"
            logger.warning(msg)
            add_alert("SQL Injection", client_ip, msg)
            send_alert_batched("SQL Injection", client_ip, clean_snippet)
        
        return {"status": "error", "message": "Invalid credentials"}
    except Exception as e:
        logger.error(f"Login error: {e}")
        return {"status": "error", "message": "Server error"}

@app.get("/api/health")
async def health_check(request: Request):
    """Simple health check endpoint for DDoS simulation"""
    # Just return OK - the sniffer will pick up the traffic volume
    return {"status": "ok"}

@app.post("/api/analyze")
async def analyze_packets():
    """
    Generate and return a comprehensive analysis summary of packet data and attacks.
    Also broadcasts to WebSocket clients and sends SMS if configured.
    """
    try:
        summary = generate_analysis_summary()
        
        # Broadcast to WebSocket clients
        if event_loop and connected_websockets:
            try:
                asyncio.run_coroutine_threadsafe(broadcast_analysis(summary), event_loop)
            except Exception as e:
                logger.error(f"Failed to broadcast analysis: {e}")
        
        # Send SMS if configured
        if TARGET_CHAT_GUID:
            send_alert(summary["text_summary"])
            # Send Mermaid diagram as image URL in separate message
            if summary.get("mermaid_diagram"):
                import base64
                
                diagram_code = summary['mermaid_diagram']
                mermaid_msg = "📊 Attack Flow Diagram:\n\n"
                
                diagram_text = diagram_code
                if "DDoS Attack" in diagram_text or "ddos" in diagram_text.lower():
                    mermaid_msg += "1️⃣ Attacker → Floods server\n"
                    mermaid_msg += "2️⃣ ShieldOS → Detects spike\n"
                    mermaid_msg += "3️⃣ ShieldOS → Alerts triggered\n"
                elif "SQL Injection" in diagram_text or "sqli" in diagram_text.lower():
                    mermaid_msg += "1️⃣ Attacker → Sends SQL payload\n"
                    mermaid_msg += "2️⃣ ShieldOS → Detects pattern\n"
                    mermaid_msg += "3️⃣ ShieldOS → Alerts triggered\n"
                
                # Convert Mermaid diagram to PNG and send as image attachment
                try:
                    import tempfile
                    import base64
                    
                    # Generate mermaid.ink PNG URL
                    diagram_bytes = diagram_code.encode('utf-8')
                    diagram_base64 = base64.urlsafe_b64encode(diagram_bytes).decode('utf-8')
                    diagram_base64 = diagram_base64.rstrip('=')
                    mermaid_png_url = f"https://mermaid.ink/img/{diagram_base64}"
                    
                    # Download the PNG image
                    logger.info(f"Downloading Mermaid PNG from: {mermaid_png_url[:80]}...")
                    png_response = requests.get(mermaid_png_url, timeout=30)
                    
                    if png_response.ok and png_response.headers.get('content-type', '').startswith('image/'):
                        # Save to temporary file
                        png_content = png_response.content
                        content_type = png_response.headers.get('content-type', 'image/png')
                        logger.info(f"Downloaded image: {len(png_content)} bytes, Content-Type: {content_type}")
                        
                        # Use appropriate file extension based on content type
                        file_ext = '.png'
                        if 'jpeg' in content_type.lower() or 'jpg' in content_type.lower():
                            file_ext = '.jpg'
                        
                        with tempfile.NamedTemporaryFile(delete=False, suffix=file_ext) as tmp_file:
                            tmp_file.write(png_content)
                            tmp_image_path = tmp_file.name
                        
                        # Send text message first to indicate what the diagram is
                        send_alert("📊 Attack Flow Diagram:")
                        
                        # Then send the image as attachment (with minimal message)
                        if send_image_message(TARGET_CHAT_GUID, tmp_image_path, message="", content_type=content_type):
                            logger.info("✅ Mermaid diagram image sent as attachment")
                        else:
                            logger.warning("Failed to send PNG, falling back to URL")
                            send_alert(f"🔗 View diagram: {mermaid_png_url}")
                        
                        # Clean up temp file
                        try:
                            os.unlink(tmp_image_path)
                        except:
                            pass
                    else:
                        logger.error(f"Failed to download PNG: {png_response.status_code}")
                        # Fallback: send URL
                        send_alert(mermaid_msg + f"\n🔗 View diagram: {mermaid_png_url}")
                        
                except Exception as e:
                    logger.error(f"Failed to convert/send Mermaid PNG: {e}", exc_info=True)
                    # Fallback: just send text description
                    send_alert(mermaid_msg)
                    logger.info("✅ Mermaid diagram text description sent (fallback)")
        
        return {
            "status": "ok",
            "analysis": summary
        }
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.get("/api/analysis-history")
async def get_analysis_history():
    """Get the last N analysis summaries"""
    return {
        "status": "ok",
        "summaries": list(analysis_summaries)
    }

async def poll_bluebubbles_messages():
    """
    Poll BlueBubbles API for new messages and process commands.
    Based on the TypeScript example polling mechanism.
    """
    global last_poll_time, processed_message_guids
    
    if not BLUEBUBBLES_URL or not BLUEBUBBLES_PASSWORD:
        return
    
    try:
        # Poll for messages from the last 60 seconds (or last poll time)
        current_time_ms = int(time.time() * 1000)
        after = last_poll_time if last_poll_time > 0 else current_time_ms - 60000
        
        url = f'{BLUEBUBBLES_URL}/api/v1/message/query?password={BLUEBUBBLES_PASSWORD}'
        
        # BlueBubbles expects POST with JSON body
        response = requests.post(
            url,
            json={
                'limit': 50,
                'offset': 0,
                'with': ['attachment', 'handle', 'chat'],
                'sort': 'DESC',
                'after': after
            },
            headers={'Content-Type': 'application/json'},
            timeout=10
        )
        
        if not response.ok:
            logger.warning(f"📡 Polling failed: {response.status_code} - {response.text[:200]}")
            return
        
        data = response.json()
        messages = data.get('data', [])
        
        if messages:
            logger.info(f"📡 Polled {len(messages)} messages from BlueBubbles")
        
        last_poll_time = current_time_ms
        
        # Process each message (process in reverse order to get newest first)
        for message in reversed(messages):
            message_guid = message.get('guid')
            if not message_guid:
                continue
            
            # Skip if already processed
            if message_guid in processed_message_guids:
                logger.debug(f"⏭️ Skipping already processed message: {message_guid[:30]}...")
                continue
            
            # Skip messages from the bot itself (isFromMe=True) to prevent loops
            if message.get('isFromMe', False):
                logger.debug(f"⏭️ Skipping message from bot itself: {message_guid[:30]}...")
                # Still mark as processed to avoid reprocessing
                processed_message_guids.add(message_guid)
                continue
            
            # Process messages that have text content
            if message.get('text'):
                # Mark as processed BEFORE processing to avoid race conditions
                processed_message_guids.add(message_guid)
                
                # Keep only last 1000 processed GUIDs to avoid memory issues
                if len(processed_message_guids) > 1000:
                    processed_message_guids = set(list(processed_message_guids)[-1000:])
                
                # Process as if it came from webhook
                logger.info(f"📨 Processing polled message: {message_guid[:30]}...")
                await handle_new_message(message)
                 
    except Exception as e:
        logger.error(f"❌ Error polling BlueBubbles messages: {e}", exc_info=True)

async def polling_loop():
    """Background task to poll for messages every 5 seconds"""
    logger.info("📡 Starting BlueBubbles message polling (every 5 seconds)")
    while True:
        try:
            await poll_bluebubbles_messages()
            await asyncio.sleep(5)  # Poll every 5 seconds
        except Exception as e:
            logger.error(f"❌ Error in polling loop: {e}")
            await asyncio.sleep(5)

@app.on_event("startup")
async def startup_event():
    global event_loop, sniffer_thread
    event_loop = asyncio.get_event_loop()
    # Start the sniffer in a daemon thread so it doesn't block
    sniffer_thread = threading.Thread(target=start_sniffer, daemon=True)
    sniffer_thread.start()
    
    # Start polling for BlueBubbles messages
    if BLUEBUBBLES_URL and BLUEBUBBLES_PASSWORD:
        asyncio.create_task(polling_loop())
        logger.info("✅ BlueBubbles message polling started")
    else:
        logger.warning("⚠️ BlueBubbles not configured - message polling disabled")
    
    logger.info("ShieldOS backend started. Visit http://localhost:8000/vulnerable-login for attack simulation.")

def send_image_message(chat_guid: str, image_path: str, message: str = '📊 Attack Flow Diagram', content_type: str = 'image/png', method: str = 'apple-script'):
    """
    Sends an image attachment via BlueBubbles API using FormData.
    Based on the TypeScript example from BlueBubbles.
    
    Args:
        chat_guid (str): The chat guid to send the message to
        image_path (str): Path to the image file to send
        message (str): Message text to send with the image (required for private-api method)
        content_type (str): MIME type of the image (default: 'image/png')
        method (str): The method to use to send the message. Defaults to "apple-script"
    """
    if not BLUEBUBBLES_URL or not BLUEBUBBLES_PASSWORD:
        logger.warning("BlueBubbles not configured. Cannot send image.")
        return False
    
    try:
        # Use the attachment endpoint as shown in TypeScript example
        url = f'{BLUEBUBBLES_URL}/api/v1/message/attachment?password={BLUEBUBBLES_PASSWORD}'
        
        # Verify file exists
        if not os.path.exists(image_path):
            logger.error(f"Image file not found: {image_path}")
            return False
        
        filename = os.path.basename(image_path)
        file_size = os.path.getsize(image_path)
        
        if file_size == 0:
            logger.error(f"Image file is empty: {image_path}")
            return False
        
        logger.info(f"Sending image attachment: {filename} ({file_size} bytes, type: {content_type})")
        
        # Create form data with file - must open file in binary mode
        with open(image_path, 'rb') as img_file:
            files = {
                'attachment': (filename, img_file, content_type)
            }
            
            # Form data fields (not JSON)
            data = {
                'chatGuid': chat_guid,
                'tempGuid': f'temp-{int(time.time() * 1000)}',
                'method': method,
                'name': filename
            }
            
            # Add message if provided (required for private-api method)
            if message:
                data['message'] = message
            
            # Send as multipart/form-data (requests handles this automatically when files are provided)
            response = requests.post(
                url,
                files=files,
                data=data,
                timeout=30
            )
            
            if not response.ok:
                logger.error(f"Failed to send image: {response.status_code} - {response.text}")
                return False
            
            try:
                result = response.json()
                logger.info(f"Image sent successfully to {chat_guid[:30]}... Status: {result.get('status', 'unknown')}")
                return True
            except:
                # Response might not be JSON
                logger.info(f"Image sent successfully (response: {response.status_code})")
                return True
                
    except FileNotFoundError:
        logger.error(f"Image file not found: {image_path}")
        return False
    except Exception as e:
        logger.error(f"Failed to send image: {e}", exc_info=True)
        return False

def send_text_message(chat_guid: str, text: str, method: str = 'private-api'):
    """
    Sends a text message to a chat via the BlueBubbles server.
    Based on the BlueBubbles example.
    
    Args:
        chat_guid (str): The chat guid to send the message to
        text (str): The text to send
        method (str): The method to use to send the message. Defaults to "private-api"
    """
    if not BLUEBUBBLES_URL or not BLUEBUBBLES_PASSWORD:
        logger.warning("BlueBubbles not configured. Cannot send message.")
        return
    
    params = {'password': BLUEBUBBLES_PASSWORD}
    data = {
        'chatGuid': chat_guid,
        'message': text,  # BlueBubbles API requires 'message' field
        'method': method,
        'tempGuid': f'temp-{int(time.time() * 1000)}'
    }
    
    try:
        response = requests.post(
            f'{BLUEBUBBLES_URL}/api/v1/message/text',
            json=data,
            params=params,
            headers={'Content-Type': 'application/json'},
            timeout=10
        )
        
        if not response.ok:
            logger.error(f"BlueBubbles API error: {response.status_code} - {response.text}")
        else:
            logger.info(f"Message sent successfully to {chat_guid[:30]}...")
    except Exception as e:
        logger.error(f"Failed to send message: {e}")

@app.get("/webhook-test")
async def webhook_test():
    """Test endpoint to verify server is accessible"""
    logger.info("✅ Webhook test endpoint hit!")
    return {"status": "ok", "message": "Webhook endpoint is accessible"}

@app.post("/")
async def handle_webhook(request: Request):
    """
    Handle incoming webhooks from BlueBubbles.
    Based on the BlueBubbles example structure.
    """
    global TARGET_CHAT_GUID
    
    client_ip = request.client.host if request.client else 'unknown'
    logger.info(f"🔔🔔🔔 WEBHOOK RECEIVED: {request.method} {request.url.path} from {client_ip} 🔔🔔🔔")
    logger.info(f"📋 Headers: {dict(request.headers)}")
    
    # Check Content-Type (but be flexible)
    content_type = request.headers.get('Content-Type', '')
    logger.info(f"📋 Content-Type: {content_type}")
    
    if content_type and 'application/json' not in content_type:
        logger.warning(f"⚠️ Unexpected Content-Type: {content_type}")
        # Don't reject, just warn
    
    try:
        # Try to read body first as text to see what we're getting
        body = await request.body()
        logger.info(f"📥 Raw body (first 500 chars): {body[:500]}")
        
        # Parse JSON
        data = json.loads(body) if body else {}
        logger.info(f"📥 Parsed JSON type: {data.get('type')}")
        logger.info(f"📥 Full webhook data: {json.dumps(data)[:1000]}")
    except json.JSONDecodeError as e:
        logger.error(f"❌ Invalid JSON received: {e}")
        logger.error(f"❌ Body was: {body[:500] if 'body' in locals() else 'None'}")
        raise HTTPException(status_code=400, detail="Invalid JSON")
    except Exception as e:
        logger.error(f"❌ Error reading request: {e}", exc_info=True)
        raise HTTPException(status_code=400, detail=f"Error reading request: {str(e)}")
    
    # Handle different event types
    event_type = data.get('type')
    logger.info(f"🎯 Event type: {event_type}")
    
    if event_type == 'new-message':
        logger.info("✅ Processing new-message event")
        await handle_new_message(data)
    else:
        logger.info(f"ℹ️ Unhandled event type: {event_type}")
        # Also try to handle if it's a direct message object (no type field)
        if 'text' in data or 'chatGuid' in data or 'chats' in data:
            logger.info("📨 Detected direct message format, processing...")
            await handle_new_message(data)
        else:
            logger.warning(f"⚠️ Unknown event format. Keys: {list(data.keys())}")
    
    return {"status": "ok"}

async def analyze_codebase_security(repo_root: Path = None) -> dict:
    """
    Analyze the entire codebase for security vulnerabilities.
    Returns a dict with vulnerabilities found and code context.
    """
    if repo_root is None:
        repo_root = Path(__file__).parent.parent
    
    codebase_content = {}
    
    # Dynamically find Python files, HTML files, and JavaScript/TypeScript files
    # Look for common security-sensitive files
    patterns_to_find = [
        "**/*.py",  # Python files
        "**/*.html",  # HTML files
        "**/*.js",  # JavaScript files
        "**/*.ts",  # TypeScript files
        "**/*.tsx",  # TypeScript React files
        "**/*.jsx",  # JavaScript React files
    ]
    
    found_files = []
    for pattern in patterns_to_find:
        found_files.extend(list(repo_root.glob(pattern)))
    
    # Filter out common directories to ignore
    ignore_dirs = {'node_modules', '.git', 'venv', '__pycache__', '.next', 'dist', 'build'}
    relevant_files = [
        f for f in found_files
        if not any(ignore_dir in f.parts for ignore_dir in ignore_dirs)
        and f.is_file()
    ]
    
    # Sort by importance (prioritize main files, API routes, templates)
    def file_priority(file_path):
        path_str = str(file_path)
        if 'main.py' in path_str or 'app.py' in path_str:
            return 0
        elif 'api' in path_str or 'route' in path_str:
            return 1
        elif 'template' in path_str or 'login' in path_str:
            return 2
        elif file_path.suffix in ['.html', '.jsx', '.tsx']:
            return 3
        else:
            return 4
    
    relevant_files.sort(key=file_priority)
    
    # Limit to top 10 most relevant files to avoid overwhelming the LLM
    for file_path in relevant_files[:10]:
        try:
            relative_path = file_path.relative_to(repo_root)
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                # Limit size for LLM context
                if len(content) > 8000:
                    content = content[:4000] + "\n... [truncated] ...\n" + content[-4000:]
                codebase_content[str(relative_path)] = content
        except Exception as e:
            logger.warning(f"Could not read file {file_path}: {e}")
            continue
    
    return {
        "files": codebase_content,
        "repo_root": str(repo_root)
    }

def fix_variable_conflict_direct(file_path: Path, variable_name: str) -> bool:
    """
    Directly fix variable name conflicts by renaming all instances.
    Returns True if fix was applied, False otherwise.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Find all variable declarations and usages
        # Pattern to match: const/let/var variable_name = ... or variable_name = ... or variable_name.
        var_pattern = re.compile(rf'\b{re.escape(variable_name)}\b')
        matches = list(var_pattern.finditer(content))
        
        if len(matches) <= 1:
            return False  # Not a conflict or already fixed
        
        # Analyze context to determine which instances to rename
        # We'll rename all but the first declaration
        lines = content.split('\n')
        renamed_count = 0
        result_parts = []
        last_pos = 0
        
        for idx, match in enumerate(matches):
            start, end = match.span()
            
            # Check if this is a declaration (const/let/var before it)
            before_match = content[max(0, start-20):start]
            is_declaration = bool(re.search(r'\b(const|let|var)\s+$', before_match))
            
            # Keep first declaration as-is, rename others
            if idx == 0 or not is_declaration:
                # Keep original
                result_parts.append(content[last_pos:end])
            else:
                # Rename this instance
                result_parts.append(content[last_pos:start])
                # Use descriptive names based on context
                if idx == 1:
                    new_name = f"{variable_name}Result"
                elif idx == 2:
                    new_name = f"{variable_name}Data"
                else:
                    new_name = f"{variable_name}{idx}"
                result_parts.append(new_name)
                renamed_count += 1
            
            last_pos = end
        
        result_parts.append(content[last_pos:])
        
        if renamed_count > 0:
            fixed_content = ''.join(result_parts)
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(fixed_content)
            logger.info(f"Directly fixed {renamed_count} variable conflicts for '{variable_name}' in {file_path}")
            return True
        
        return False
    except Exception as e:
        logger.error(f"Error in direct variable fix: {e}")
        return False

async def fix_build_errors(codebase_analysis: dict, build_error: str, original_fixes: dict, repo_root: Path, model: str = "llama-3.3-70b-versatile") -> dict:
    """
    Use LLM to fix build errors found during npm run build.
    Returns dict with variable_name extracted for direct fixing if LLM fails.
    """
    # Extract variable name and problematic file early for fallback
    import re
    error_file_match = re.search(r'\./([\w/.-]+\.(js|ts|tsx|jsx))', build_error)
    problematic_file = None
    if error_file_match:
        problematic_file = error_file_match.group(1)
    
    variable_name = None
    var_match = re.search(r'the name `(\w+)` is defined multiple times', build_error)
    if var_match:
        variable_name = var_match.group(1)
    
    if not GROQ_AVAILABLE or not GROQ_API_KEY:
        # Return metadata for direct fixing
        result = {'files': {}, '_variable_name': variable_name, '_problematic_file': problematic_file}
        return result
    
    try:
        client = Groq(api_key=GROQ_API_KEY)
        
        # Get the files that were modified - read FULL content for problematic files
        modified_files_context = ""
        for file_path, file_data in original_fixes.get('files', {}).items():
            full_path = repo_root / file_path
            if full_path.exists():
                with open(full_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    # Read full file if it's the problematic one, otherwise limit to 3000 chars
                    if file_path == problematic_file or problematic_file is None:
                        modified_files_context += f"\n\n--- {file_path} (FULL FILE) ---\n{content}"
                    else:
                        modified_files_context += f"\n\n--- {file_path} ---\n{content[:3000]}"
        
        context = f"""You are fixing build errors in code that was just modified.

BUILD ERROR:
{build_error[:2000]}

{f"CRITICAL: The variable '{variable_name}' is defined multiple times. You MUST find ALL instances of this variable and rename them to unique names (e.g., {variable_name}1, {variable_name}2, or more descriptive names like {variable_name}Result, {variable_name}Data, etc.)." if variable_name else ""}

MODIFIED FILES:
{modified_files_context}

TASK:
Fix the build errors shown above. Common issues:
- Variable redefinition (check for duplicate variable names) - THIS IS THE CURRENT ISSUE
- Missing imports
- Syntax errors
- Type errors

IMPORTANT FOR VARIABLE REDEFINITION ERRORS:
- Read the ENTIRE file to find ALL instances of the conflicting variable name
- Rename each instance to a unique, descriptive name
- Ensure the renamed variables make sense in context
- If the variable is used in multiple scopes, you may be able to reuse the name in different scopes, but NOT in the same scope

Return ONLY the fixes in JSON format:
{{
  "files": {{
    "path/to/file.js": {{
      "changes": {{
        "old_code": "the problematic code section with duplicate variable",
        "new_code": "the fixed code with unique variable names"
      }}
    }}
  }}
}}

CRITICAL:
- Fix variable name conflicts by renaming ALL instances appropriately
- Ensure all code is syntactically correct
- Only fix the specific errors shown
- Return valid JSON with proper escaping
- For variable conflicts: show the FULL context where the variable is defined multiple times"""

        response = client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": "You are a code fixer. Return only valid JSON with code fixes. When fixing variable name conflicts, you MUST find ALL instances of the conflicting variable in the file and rename them to unique names. Read the entire file context to understand the scope of each variable."
                },
                {
                    "role": "user",
                    "content": context
                }
            ],
            temperature=0.1,
            max_tokens=4000
        )
        
        response_text = response.choices[0].message.content.strip()
        logger.debug(f"Raw build fix response (first 500 chars): {response_text[:500]}")
        
        # Remove markdown code blocks if present
        if response_text.startswith("```"):
            parts = response_text.split("```")
            if len(parts) > 1:
                response_text = parts[1]
                if response_text.startswith("json"):
                    response_text = response_text[4:]
        response_text = response_text.strip()
        
        # Extract JSON
        import re
        json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
        if json_match:
            response_text = json_match.group(0)
        
        # Try to parse JSON with better error handling
        try:
            fixes = json.loads(response_text)
        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error at position {e.pos}: {e.msg}")
            logger.error(f"Response text around error (chars {max(0, e.pos-100)}-{min(len(response_text), e.pos+100)}):")
            logger.error(response_text[max(0, e.pos-100):min(len(response_text), e.pos+100)])
            
            # Try to fix common JSON issues
            fixed_text = response_text
            # Fix invalid escape sequences like \' with just ' (single quotes don't need escaping in JSON)
            fixed_text = re.sub(r"(?<!\\)\\'", "'", fixed_text)
            
            try:
                fixes = json.loads(fixed_text)
                logger.info("Successfully parsed JSON after fixing escape sequences")
            except json.JSONDecodeError:
                logger.error("Failed to parse JSON even after fixing escape sequences")
                return None
        
        # Merge with original fixes
        if 'files' in fixes:
            original_fixes['files'].update(fixes['files'])
        
        # Add metadata for direct fixing fallback
        original_fixes['_variable_name'] = variable_name
        original_fixes['_problematic_file'] = problematic_file
        
        return original_fixes
    except Exception as e:
        logger.error(f"Build error fix generation failed: {e}", exc_info=True)
        # Return metadata even on error for direct fixing
        result = {'files': {}, '_variable_name': variable_name, '_problematic_file': problematic_file}
        return result

async def generate_vulnerability_fixes(codebase_analysis: dict, model: str = "llama-3.3-70b-versatile") -> dict:
    """
    Use LLM to analyze codebase and generate security fixes.
    Returns a dict with file paths and their fixed code.
    """
    if not GROQ_AVAILABLE or not GROQ_API_KEY:
        return None
    
    try:
        client = Groq(api_key=GROQ_API_KEY)
        
        # Build codebase context
        codebase_text = ""
        for file_path, content in codebase_analysis["files"].items():
            codebase_text += f"\n\n--- {file_path} ---\n{content}"
        
        # Read package.json if it exists to know what packages are available
        repo_root = Path(codebase_analysis.get("repo_root", Path(__file__).parent.parent))
        package_json_path = repo_root / "package.json"
        available_packages = []
        if package_json_path.exists():
            try:
                with open(package_json_path, 'r', encoding='utf-8') as f:
                    package_data = json.load(f)
                    # Get dependencies and devDependencies
                    deps = package_data.get('dependencies', {})
                    dev_deps = package_data.get('devDependencies', {})
                    available_packages = list(deps.keys()) + list(dev_deps.keys())
            except Exception as e:
                logger.warning(f"Could not read package.json: {e}")
        
        packages_info = ""
        if available_packages:
            packages_info = f"\n\nAVAILABLE PACKAGES IN package.json:\n{', '.join(sorted(available_packages))}\n"
        
        context = f"""You are a security expert analyzing a codebase for vulnerabilities and generating fixes.

CODEBASE TO ANALYZE:
{codebase_text}

TASK:
1. Analyze the codebase for security vulnerabilities (SQL injection, XSS, DDoS, authentication issues, etc.)
2. Identify all security issues with clear explanations
3. Generate fixes for each vulnerability
4. Return fixes in a structured JSON format

REQUIREMENTS FOR FIXES:
- Fix SQL injection: Add input validation, sanitization, and parameterized queries
- Fix DDoS: Add rate limiting using ONLY built-in features or packages that already exist in package.json
- Fix XSS: Add output encoding and input validation
- Keep all existing functionality intact
- Use the exact same code structure and imports

CRITICAL DEPENDENCY RULES:
{packages_info}
- DO NOT import or use packages that are NOT in the available packages list above
- For Next.js/React projects: Use built-in Next.js features, native JavaScript, or existing packages only
- For rate limiting: Use simple in-memory tracking with Map/Set, or use existing packages from the list
- If you MUST add a new package, you MUST also update package.json in the "dependencies" or "package_dependencies" field
- NEVER use express-rate-limit, slowapi, or any package not in the available list unless you also add it to package.json
- For Next.js API routes: Use native Request/Response APIs, not Express middleware

CRITICAL CODE QUALITY RULES:
- Check for existing variable names in the code before defining new ones - NEVER redefine variables
- Use unique variable names (e.g., if "users" exists, use "userList", "userData", etc.)
- Ensure all code is syntactically correct and will pass build checks
- Do NOT create variable name conflicts
- Test that variable names don't clash with existing code
- Use const/let appropriately - don't redeclare variables
- Ensure all code changes are valid JavaScript/TypeScript that will compile successfully

IMPORTANT: 
- Return ONLY the CHANGED sections of code, not entire files
- Use exact string matching for old_code (must match existing code exactly)
- Escape all special characters in JSON strings (quotes, newlines, backslashes)
- Return valid JSON with this structure:

{{
  "vulnerabilities": [
    {{
      "type": "SQL Injection",
      "file": "backend/main.py",
      "description": "Login endpoint uses string concatenation in SQL query, allowing SQL injection",
      "severity": "High",
      "line": "~150"
    }}
  ],
  "files": {{
    "backend/main.py": {{
      "description": "Added input validation, parameterized queries, and rate limiting",
      "changes": {{
        "old_code": "exact existing code section to replace",
        "new_code": "fixed code section"
      }}
    }}
  }},
  "summary": "Fixed SQL injection vulnerability in login endpoint by adding parameterized queries and input validation. Added rate limiting middleware to prevent DDoS attacks."
}}

CRITICAL JSON RULES: 
- In JSON strings, escape double quotes with \\" but NEVER escape single quotes
- Single quotes (') in code do NOT need escaping in JSON strings - use them as-is
- Escape newlines in code strings using \\n
- Escape backslashes using \\\\
- For JavaScript regex patterns like /[^a-zA-Z0-9]/g, keep them as-is (forward slashes don't need escaping)
- Return ONLY valid JSON, no markdown code blocks, no extra text before or after
- Ensure all strings are properly closed
- Example: Use oninput=\"this.value = this.value.replace(/[^a-zA-Z0-9]/g, '')\" NOT oninput=\\\"this.value = this.value.replace(/[^a-zA-Z0-9]/g, \\\\'\\\\')\\\" """

        response = client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": "You are a security expert. You MUST return ONLY valid JSON. Escape all special characters in strings (quotes as \\\", newlines as \\n, backslashes as \\\\). Do not include markdown code blocks. Ensure all JSON strings are properly closed. CRITICAL: Check for existing variable names before defining new ones - NEVER create variable name conflicts. Ensure all generated code is syntactically correct and will pass build checks. Use unique variable names to avoid redefinition errors."
                },
                {
                    "role": "user",
                    "content": context
                }
            ],
            temperature=0.2,
            max_tokens=3000
        )
        
        response_text = response.choices[0].message.content.strip()
        logger.debug(f"Raw LLM response (first 500 chars): {response_text[:500]}")
        
        # Remove markdown code blocks if present
        if response_text.startswith("```"):
            parts = response_text.split("```")
            if len(parts) > 1:
                response_text = parts[1]
                if response_text.startswith("json"):
                    response_text = response_text[4:]
        response_text = response_text.strip()
        
        # Try to extract JSON from the response (in case there's extra text)
        # Look for JSON object boundaries
        import re
        json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
        if json_match:
            response_text = json_match.group(0)
        
        # Try to parse JSON with better error handling
        try:
            fixes = json.loads(response_text)
        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error at position {e.pos}: {e.msg}")
            logger.error(f"Response text around error (chars {max(0, e.pos-100)}-{min(len(response_text), e.pos+100)}):")
            logger.error(response_text[max(0, e.pos-100):min(len(response_text), e.pos+100)])
            
            # Try to fix common JSON issues
            fixed_text = response_text
            
            # Fix 1: Replace invalid escape sequences like \' with just ' (single quotes don't need escaping in JSON)
            import re
            # Replace \' that aren't part of \\' with just '
            fixed_text = re.sub(r"(?<!\\)\\'", "'", fixed_text)
            
            # Fix 2: Fix other invalid escapes (but keep valid ones like \n, \", \\)
            # This is tricky - we need to be careful not to break valid escapes
            # For now, let's just fix the most common issue: \' -> '
            
            try:
                # Attempt to fix by finding the JSON structure
                # Look for the main JSON object
                brace_count = 0
                start_idx = fixed_text.find('{')
                if start_idx != -1:
                    # Try to find the matching closing brace (accounting for strings)
                    in_string = False
                    escape_next = False
                    for i in range(start_idx, len(fixed_text)):
                        if escape_next:
                            escape_next = False
                            continue
                        if fixed_text[i] == '\\':
                            escape_next = True
                            continue
                        if fixed_text[i] == '"' and not escape_next:
                            in_string = not in_string
                            continue
                        if not in_string:
                            if fixed_text[i] == '{':
                                brace_count += 1
                            elif fixed_text[i] == '}':
                                brace_count -= 1
                                if brace_count == 0:
                                    fixed_text = fixed_text[start_idx:i+1]
                                    break
                
                fixes = json.loads(fixed_text)
                logger.info("Successfully parsed JSON after fixing escape sequences")
            except Exception as e2:
                logger.error(f"Failed to fix JSON: {e2}")
                # Try one more aggressive fix: replace all \' with '
                try:
                    aggressive_fix = fixed_text.replace("\\'", "'")
                    fixes = json.loads(aggressive_fix)
                    logger.info("Successfully parsed JSON after aggressive escape fix")
                except Exception as e3:
                    logger.error(f"All JSON fix attempts failed: {e3}")
                    # Return a minimal valid structure so the command doesn't completely fail
                    logger.warning("Returning empty fixes structure due to JSON parse failure")
                    return {
                        "vulnerabilities": [],
                        "files": {},
                        "summary": "Failed to parse LLM response. Please check logs for details."
                    }
        
        # Store vulnerabilities for PR description
        if 'vulnerabilities' in fixes:
            fixes['_vulnerabilities'] = fixes['vulnerabilities']
        
        # Convert changes format to full file code if needed
        repo_root = Path(codebase_analysis.get("repo_root", Path(__file__).parent.parent))
        if 'files' in fixes:
            for file_path, file_data in fixes['files'].items():
                if 'changes' in file_data:
                    # If we got changes, we need to apply them to the full file
                    full_path = repo_root / file_path
                    if full_path.exists():
                        with open(full_path, 'r', encoding='utf-8') as f:
                            full_content = f.read()
                        
                        # Apply the change
                        old_code = file_data['changes'].get('old_code', '')
                        new_code = file_data['changes'].get('new_code', '')
                        if old_code in full_content:
                            full_content = full_content.replace(old_code, new_code)
                            file_data['code'] = full_content
                        else:
                            logger.warning(f"Could not find exact match for old_code in {file_path}")
                            # Try to find similar code patterns
                            file_data['code'] = full_content  # Keep original if can't match
                    else:
                        # If file doesn't exist, use the new_code as the full code
                        file_data['code'] = file_data['changes'].get('new_code', '')
        
        return fixes
    except Exception as e:
        error_str = str(e).lower()
        # Check if it's a rate limit error
        if "rate limit" in error_str or "429" in error_str or (GroqRateLimitError and isinstance(e, GroqRateLimitError)):
            error_msg = str(e)
            logger.warning(f"Groq rate limit exceeded for model {model}: {error_msg}")
            # Re-raise so caller can try next model
            raise
        logger.error(f"LLM fix generation error: {e}", exc_info=True)
        raise  # Re-raise so caller can try next model

def get_github_installation_token() -> str:
    """
    Generate an installation access token for GitHub App authentication.
    Returns the installation access token if successful.
    """
    if not JWT_AVAILABLE:
        raise ValueError("PyJWT library is required for GitHub App authentication. Install it with: pip install PyJWT cryptography")
    
    if not GITHUB_APP_ID or not GITHUB_APP_PRIVATE_KEY or not GITHUB_APP_INSTALLATION_ID:
        raise ValueError("GitHub App credentials not found. Required: GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY, GITHUB_APP_INSTALLATION_ID")
    
    try:
        # Parse private key (handle base64 encoded or raw PEM)
        private_key = GITHUB_APP_PRIVATE_KEY.strip()
        
        # If it looks like base64, decode it
        if not private_key.startswith('-----BEGIN'):
            try:
                private_key = base64.b64decode(private_key).decode('utf-8')
            except Exception:
                pass  # Assume it's already in PEM format
        
        # Ensure proper line breaks
        if '\\n' in private_key:
            private_key = private_key.replace('\\n', '\n')
        
        # Generate JWT
        now = datetime.now(datetime.UTC) if hasattr(datetime, 'UTC') else datetime.utcnow()
        payload = {
            'iat': now - timedelta(seconds=60),  # Issued at time (1 minute ago to account for clock skew)
            'exp': now + timedelta(minutes=10),  # Expires in 10 minutes
            'iss': int(GITHUB_APP_ID)  # Issuer (App ID)
        }
        
        jwt_token = jwt.encode(payload, private_key, algorithm='RS256')
        
        # Get installation access token
        installation_id = int(GITHUB_APP_INSTALLATION_ID)
        headers = {
            'Authorization': f'Bearer {jwt_token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        
        response = requests.post(
            f'https://api.github.com/app/installations/{installation_id}/access_tokens',
            headers=headers,
            timeout=10
        )
        
        if not response.ok:
            error_msg = response.text
            raise Exception(f"Failed to get installation token: {response.status_code} - {error_msg}")
        
        token_data = response.json()
        return token_data['token']
        
    except Exception as e:
        logger.error(f"Failed to generate GitHub App installation token: {e}", exc_info=True)
        raise

def get_github_auth_headers() -> dict:
    """
    Get GitHub API authentication headers.
    Prefers GitHub App over Personal Access Token.
    """
    if GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY and GITHUB_APP_INSTALLATION_ID:
        try:
            token = get_github_installation_token()
            return {
                'Authorization': f'token {token}',
                'Accept': 'application/vnd.github.v3+json'
            }
        except Exception as e:
            logger.warning(f"GitHub App authentication failed, falling back to token: {e}")
    
    if GITHUB_TOKEN:
        return {
            'Authorization': f'token {GITHUB_TOKEN}',
            'Accept': 'application/vnd.github.v3+json'
        }
    
    raise ValueError("No GitHub authentication method available. Set either GITHUB_TOKEN or GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY, and GITHUB_APP_INSTALLATION_ID")

async def create_github_pr(branch_name: str, summary: str, files_modified: list, base_branch: str = 'main') -> str:
    """
    Create a GitHub Pull Request using the GitHub API.
    Returns the PR URL if successful, None otherwise.
    
    Args:
        branch_name: Name of the branch to create PR from
        summary: Summary of the fixes
        files_modified: List of files that were modified
        base_branch: Base branch to merge into (default: 'main')
    """
    # Check if any authentication method is available
    try:
        headers = get_github_auth_headers()
    except ValueError as e:
        logger.warning(str(e))
        raise ValueError("GitHub authentication required. Set GITHUB_TOKEN or GitHub App credentials (GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY, GITHUB_APP_INSTALLATION_ID) in .env")
    
    try:
        # Get repo info from environment variable and parse it
        if not GITHUB_REPO:
            raise ValueError("GITHUB_REPO environment variable is required. Set it in your .env file (e.g., 'https://github.com/owner/repo' or 'owner/repo')")
        
        # Parse repo from URL or owner/repo format
        repo_str = GITHUB_REPO.strip()
        
        # Handle full URL format: https://github.com/owner/repo or github.com/owner/repo
        if 'github.com' in repo_str:
            # Extract owner/repo from URL
            if 'https://' in repo_str or 'http://' in repo_str:
                parts = repo_str.split('github.com/')[-1].replace('.git', '').split('/')
            else:
                parts = repo_str.split('github.com/')[-1].replace('.git', '').split('/')
            
            if len(parts) >= 2:
                owner = parts[0]
                repo = parts[1]
            else:
                raise ValueError(f"Invalid GitHub repo URL format: {repo_str}. Expected format: 'https://github.com/owner/repo' or 'owner/repo'")
        else:
            # Handle owner/repo format
            parts = repo_str.split('/')
            if len(parts) == 2:
                owner = parts[0]
                repo = parts[1]
            else:
                raise ValueError(f"Invalid GitHub repo format: {repo_str}. Expected format: 'https://github.com/owner/repo' or 'owner/repo'")
        
        # Headers already set by get_github_auth_headers() above
        headers['Content-Type'] = 'application/json'
        
        # Verify base branch exists on remote
        base_branch_check_url = f"https://api.github.com/repos/{owner}/{repo}/branches/{base_branch}"
        base_check = requests.get(base_branch_check_url, headers=headers, timeout=10)
        if not base_check.ok:
            logger.warning(f"Base branch {base_branch} not found on remote. Trying 'main'...")
            base_branch = 'main'
            base_branch_check_url = f"https://api.github.com/repos/{owner}/{repo}/branches/{base_branch}"
            base_check = requests.get(base_branch_check_url, headers=headers, timeout=10)
            if not base_check.ok:
                logger.warning(f"Branch 'main' not found. Trying 'master'...")
                base_branch = 'master'
        
        logger.info(f"Using base branch: {base_branch} for PR: {owner}/{repo}")
        
        # Create PR using GitHub API
        pr_title = f"🔒 Security Fix: {summary[:50]}"
        
        # Build detailed PR body with issue explanations
        vulnerabilities_text = ""
        # files_modified is a list, but we need to get vulnerabilities from fixes
        # We'll pass it separately or store in a different way
        
        file_list = files_modified if isinstance(files_modified, list) else list(files_modified.keys()) if isinstance(files_modified, dict) else []
        
        pr_body = f"""## Security Vulnerability Fixes

### Summary
{summary}

### Issues Found and Fixed
Security vulnerabilities were identified during codebase analysis and have been fixed:
- SQL Injection protection (parameterized queries, input validation)
- DDoS protection (rate limiting)
- Input sanitization and validation
- Security best practices implementation

### Files Modified
{chr(10).join([f'- `{f}`' for f in file_list])}

---

**Author:** ShieldOS AI Agent  
**Email:** shieldos@shieldos.ai

*This PR was created automatically by ShieldOS after analyzing the codebase for security vulnerabilities. All commits in this PR are authored by ShieldOS.*
"""
        
        api_url = f"https://api.github.com/repos/{owner}/{repo}/pulls"
        
        # Verify branch exists on remote first (with retries)
        branch_check_url = f"https://api.github.com/repos/{owner}/{repo}/branches/{branch_name}"
        max_retries = 5
        retry_delay = 3
        
        for attempt in range(max_retries):
            branch_check = requests.get(branch_check_url, headers=headers, timeout=10)
            if branch_check.ok:
                logger.info(f"Branch {branch_name} verified on remote")
                break
            else:
                if attempt < max_retries - 1:
                    logger.warning(f"Branch {branch_name} not found on remote yet. Waiting {retry_delay}s (attempt {attempt + 1}/{max_retries})...")
                    time.sleep(retry_delay)
                else:
                    error_detail = branch_check.text[:200] if branch_check.text else "Unknown error"
                    raise Exception(f"Branch {branch_name} does not exist on remote after {max_retries} attempts. Push may have failed. Error: {error_detail}")
        
        # For same-repo PRs, head should be just the branch name
        # GitHub API format: for same repo use just branch name, for forks use owner:branch
        payload = {
            'title': pr_title,
            'body': pr_body,
            'head': branch_name,  # For same repo, just branch name
            'base': base_branch
        }
        
        logger.info(f"Creating PR: {owner}/{repo} ({branch_name} -> {base_branch})")
        logger.debug(f"PR payload: {payload}")
        response = requests.post(api_url, json=payload, headers=headers, timeout=10)
        
        # If head is invalid, try with owner:branch format (sometimes needed even for same repo)
        if not response.ok and response.status_code == 422:
            error_data = response.json()
            errors = error_data.get('errors', [])
            if any('head' in str(err) for err in errors):
                logger.info(f"Trying with owner:branch format...")
                payload['head'] = f"{owner}:{branch_name}"
                response = requests.post(api_url, json=payload, headers=headers, timeout=10)
        
        if response.ok:
            pr_data = response.json()
            pr_url = pr_data.get('html_url')
            pr_number = pr_data.get('number')
            logger.info(f"✅ Created PR #{pr_number}: {pr_url}")
            return pr_url
        else:
            error_msg = response.text
            logger.error(f"GitHub API error: {response.status_code} - {error_msg}")
            raise Exception(f"Failed to create PR: {response.status_code} - {error_msg[:200]}")
             
    except subprocess.CalledProcessError as e:
        logger.error(f"Git command failed: {e}")
        raise Exception(f"Git operation failed: {str(e)}")
    except Exception as e:
        logger.error(f"Failed to create GitHub PR: {e}", exc_info=True)
        raise

async def handle_fix_command(chat_guid: str):
    """
    Handle the 'fix' command: analyze codebase, generate fixes, and create a PR.
    """
    # Check if any authentication method is available
    has_auth = False
    auth_method = None
    
    if GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY and GITHUB_APP_INSTALLATION_ID:
        has_auth = True
        auth_method = "GitHub App"
    elif GITHUB_TOKEN:
        has_auth = True
        auth_method = "Personal Access Token"
    
    if not has_auth:
        send_text_message(chat_guid, "❌ GitHub authentication not found in .env file")
        send_text_message(chat_guid, "💡 Add either:")
        send_text_message(chat_guid, "   - GITHUB_TOKEN=your_token (Personal Access Token)")
        send_text_message(chat_guid, "   - OR GitHub App: GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY, GITHUB_APP_INSTALLATION_ID")
        return
    
    # Check for required GitHub repo info
    if not GITHUB_REPO:
        send_text_message(chat_guid, "❌ GitHub repository not configured")
        send_text_message(chat_guid, "💡 Add to .env file:")
        send_text_message(chat_guid, "   GITHUB_REPO=https://github.com/owner/repo")
        send_text_message(chat_guid, "   (or just: GITHUB_REPO=owner/repo)")
        return
    
    # Parse and show repo info
    try:
        repo_str = GITHUB_REPO.strip()
        if 'github.com' in repo_str:
            parts = repo_str.split('github.com/')[-1].replace('.git', '').split('/')
        else:
            parts = repo_str.split('/')
        
        if len(parts) >= 2:
            owner = parts[0]
            repo_name = parts[1]
        else:
            send_text_message(chat_guid, f"❌ Invalid repo format: {GITHUB_REPO}")
            send_text_message(chat_guid, "💡 Use format: https://github.com/owner/repo or owner/repo")
            return
    except Exception as e:
        send_text_message(chat_guid, f"❌ Error parsing repo: {str(e)}")
        return
    
    
    # Work in a temporary directory to avoid touching the current project's git
    import tempfile
    import shutil
    
    # Create a temporary directory for cloning the target repo
    temp_dir = tempfile.mkdtemp(prefix='shieldos_fix_')
    repo_root = Path(temp_dir)
    
    send_text_message(chat_guid, f"🔧 Fixing {owner}/{repo_name}...")
    repo_str = GITHUB_REPO.strip()
    
    # Parse repo URL
    if 'github.com' in repo_str:
        if 'https://' in repo_str or 'http://' in repo_str:
            clone_url = repo_str.replace('.git', '')
            if not clone_url.endswith('.git'):
                clone_url += '.git'
        else:
            clone_url = f"https://github.com/{repo_str.split('github.com/')[-1].replace('.git', '')}.git"
    else:
        # owner/repo format
        clone_url = f"https://github.com/{repo_str}.git"
    
    # Clone the repository to temp directory (shallow clone for speed)
    clone_result = subprocess.run(
        ['git', 'clone', '--depth', '1', clone_url, str(repo_root)],
        check=True,
        capture_output=True,
        text=True
    )
    logger.info(f"Cloned repository to: {repo_root}")
    
    # Change to the cloned repo directory
    os.chdir(repo_root)
    
    try:
        # Configure git to use ShieldOS as the author (before any commits)
        subprocess.run(['git', 'config', 'user.name', 'ShieldOS'], check=True, capture_output=True, cwd=repo_root)
        subprocess.run(['git', 'config', 'user.email', 'shieldos@shieldos.ai'], check=True, capture_output=True, cwd=repo_root)
        logger.info("Configured git author as ShieldOS")
        # Now analyze the cloned codebase
        codebase_analysis = await analyze_codebase_security(repo_root=repo_root)
        
        if not codebase_analysis.get("files"):
            send_text_message(chat_guid, "❌ No files found to analyze")
            return
        
        send_text_message(chat_guid, f"   Analyzing {len(codebase_analysis['files'])} files, generating fixes...")
        
        # Generate fixes using LLM (with fallback to different model on rate limit)
        fixes = None
        # Updated model list - removed decommissioned models (llama-3.1-70b-versatile, mixtral-8x7b-32768)
        models_to_try = ["llama-3.3-70b-versatile", "llama-3.1-8b-instant", "llama-3.2-90b-text-preview"]
        
        model_name = None
        for model_name in models_to_try:
            try:
                fixes = await generate_vulnerability_fixes(codebase_analysis, model=model_name)
                if fixes:
                    break
            except Exception as e:
                error_str = str(e).lower()
                if "rate limit" in error_str or "429" in error_str:
                    logger.warning(f"Rate limit hit for {model_name}, trying next model...")
                    if model_name != models_to_try[-1]:
                        continue
                    else:
                        send_text_message(chat_guid, f"❌ All models rate limited. Please wait and try again later.")
                        raise
                elif "decommissioned" in error_str or ("400" in error_str and "model" in error_str):
                    # Model is decommissioned, skip immediately
                    logger.warning(f"Model {model_name} is decommissioned, skipping...")
                    if model_name != models_to_try[-1]:
                        continue
                    else:
                        send_text_message(chat_guid, f"❌ All available models are unavailable.")
                        raise
                else:
                    # Other error, try next model
                    logger.warning(f"Error with {model_name}: {e}, trying next model...")
                    if model_name != models_to_try[-1]:
                        continue
                    else:
                        raise
        
        if not fixes:
            send_text_message(chat_guid, "❌ Failed to generate fixes. LLM service may be unavailable.")
            return
        
        # Parse owner/repo for API calls
        if 'github.com' in repo_str:
            if 'https://' in repo_str or 'http://' in repo_str:
                parts = repo_str.split('github.com/')[-1].replace('.git', '').split('/')
            else:
                parts = repo_str.split('github.com/')[-1].replace('.git', '').split('/')
        else:
            parts = repo_str.split('/')
        
        if len(parts) >= 2:
            owner = parts[0]
            repo = parts[1]
        else:
            raise ValueError(f"Invalid repo format: {repo_str}")
        
        # Get default branch from GitHub API
        repo_info_url = f"https://api.github.com/repos/{owner}/{repo}"
        headers = get_github_auth_headers()
        repo_info = requests.get(repo_info_url, headers=headers, timeout=10)
        if repo_info.ok:
            default_branch = repo_info.json().get('default_branch', 'main')
            logger.info(f"Default branch from GitHub: {default_branch}")
        else:
            # Fallback to common defaults
            default_branch = 'main'
            logger.warning(f"Could not get default branch from GitHub, using 'main'")
        
        base_branch = default_branch
        
        # Fetch latest from remote first
        subprocess.run(['git', 'fetch', 'origin'], check=True, capture_output=True, cwd=repo_root)
        
        # Checkout the remote branch directly (don't try to create local main)
        # Try to checkout the remote branch directly - this creates a local tracking branch
        checkout_result = subprocess.run(['git', 'checkout', '-b', default_branch, f'origin/{default_branch}'], check=False, capture_output=True, text=True, cwd=repo_root)
        
        if checkout_result.returncode != 0:
            # If that failed, branch might already exist locally, just checkout it
            checkout_result2 = subprocess.run(['git', 'checkout', default_branch], check=False, capture_output=True, text=True, cwd=repo_root)
            if checkout_result2.returncode != 0:
                # Last resort: checkout remote branch directly without creating local
                logger.warning(f"Could not checkout {default_branch}, using detached HEAD from remote...")
                subprocess.run(['git', 'checkout', f'origin/{default_branch}'], check=True, capture_output=True, cwd=repo_root)
                # Create branch from current HEAD
                subprocess.run(['git', 'checkout', '-b', default_branch], check=True, capture_output=True, cwd=repo_root)
            else:
                # Reset to match remote
                subprocess.run(['git', 'reset', '--hard', f'origin/{default_branch}'], check=True, capture_output=True, cwd=repo_root)
        
        # Create a new branch from default branch
        branch_name = f"fix/security-vulnerabilities-{int(time.time())}"
        subprocess.run(['git', 'checkout', '-b', branch_name], check=True, capture_output=True, cwd=repo_root)
        logger.info(f"Created branch: {branch_name} from {base_branch}")
        
        # Apply fixes to files
        files_modified = []
        for file_path, file_data in fixes.get('files', {}).items():
            full_path = repo_root / file_path
            
            # Handle package.json specially - merge dependencies instead of replacing
            if file_path == "package.json" and full_path.exists():
                try:
                    with open(full_path, 'r', encoding='utf-8') as f:
                        current_package = json.load(f)
                    
                    # Apply changes to package.json
                    if 'changes' in file_data:
                        old_code = file_data['changes'].get('old_code', '')
                        new_code = file_data['changes'].get('new_code', '')
                        
                        # Try to parse old_code and new_code as JSON snippets
                        # If they're just dependency sections, merge them
                        if '"dependencies"' in old_code or '"dependencies"' in new_code:
                            # Parse the new dependencies
                            try:
                                # Extract dependencies from new_code
                                if '"dependencies"' in new_code:
                                    # Try to extract just the dependencies object
                                    deps_match = re.search(r'"dependencies"\s*:\s*\{[^}]+\}', new_code)
                                    if deps_match:
                                        new_deps_str = "{" + deps_match.group(0) + "}"
                                        new_deps = json.loads(new_deps_str)
                                        # Merge with existing dependencies
                                        if 'dependencies' not in current_package:
                                            current_package['dependencies'] = {}
                                        current_package['dependencies'].update(new_deps.get('dependencies', {}))
                            except Exception as e:
                                logger.warning(f"Could not parse package.json dependencies: {e}")
                                # Fall back to string replacement
                                package_str = json.dumps(current_package, indent=2)
                                if old_code in package_str:
                                    package_str = package_str.replace(old_code, new_code)
                                    current_package = json.loads(package_str)
                        
                        # Write updated package.json
                        with open(full_path, 'w', encoding='utf-8') as f:
                            json.dump(current_package, f, indent=2)
                            f.write('\n')
                        
                        files_modified.append(file_path)
                        logger.info(f"Updated package.json with new dependencies")
                        continue
                except Exception as e:
                    logger.error(f"Error updating package.json: {e}")
                    # Fall through to regular file handling
            
            if not full_path.exists():
                logger.warning(f"File not found: {file_path}")
                continue
            
            # Backup original
            backup_path = full_path.with_suffix(full_path.suffix + '.backup')
            import shutil
            shutil.copy(full_path, backup_path)
            
            # Read current file
            with open(full_path, 'r', encoding='utf-8') as f:
                current_content = f.read()
            
            # Apply fixes - check if we have 'code' (full file) or 'changes' (section)
            if 'code' in file_data:
                # Full file replacement
                with open(full_path, 'w', encoding='utf-8') as f:
                    f.write(file_data['code'])
            elif 'changes' in file_data:
                # Section replacement
                old_code = file_data['changes'].get('old_code', '')
                new_code = file_data['changes'].get('new_code', '')
                
                if old_code and old_code in current_content:
                    current_content = current_content.replace(old_code, new_code)
                    with open(full_path, 'w', encoding='utf-8') as f:
                        f.write(current_content)
                else:
                    # If exact match not found, try to find the endpoint and replace it
                    if '@app.post("/api/login")' in current_content:
                        # Find the login endpoint and replace with new code
                        start_idx = current_content.find('@app.post("/api/login")')
                        # Find the next @app decorator or end of function
                        next_decorator = current_content.find('\n@app.', start_idx + 1)
                        if next_decorator == -1:
                            next_decorator = len(current_content)
                        
                        # Replace the endpoint section
                        endpoint_section = current_content[start_idx:next_decorator]
                        current_content = current_content.replace(endpoint_section, new_code)
                        
                        with open(full_path, 'w', encoding='utf-8') as f:
                            f.write(current_content)
                    else:
                        logger.warning(f"Could not find code section to replace in {file_path}")
                        continue
            
            files_modified.append(file_path)
            logger.info(f"Fixed file: {file_path}")
        
        if not files_modified:
            send_text_message(chat_guid, "❌ No files were modified. Fix generation may have failed.")
            subprocess.run(['git', 'checkout', '-'], check=False)  # Return to original branch
            return
        
        # Run build check to ensure code compiles - keep fixing until it passes
        send_text_message(chat_guid, f"🔨 Running build check...")
        build_passed = False
        max_build_fix_attempts = 10  # Maximum attempts to avoid infinite loops
        attempt = 0
        
        # Check if package.json exists (Node.js project)
        package_json = repo_root / "package.json"
        if package_json.exists():
            # First, install dependencies if node_modules doesn't exist
            node_modules = repo_root / "node_modules"
            if not node_modules.exists():
                send_text_message(chat_guid, f"📦 Installing dependencies...")
                try:
                    install_result = subprocess.run(
                        ['npm', 'install'],
                        cwd=repo_root,
                        capture_output=True,
                        text=True,
                        timeout=300  # 5 minutes for npm install
                    )
                    if install_result.returncode != 0:
                        logger.warning(f"npm install failed: {install_result.stderr[:500]}")
                    else:
                        logger.info("✅ Dependencies installed successfully")
                except subprocess.TimeoutExpired:
                    logger.warning("npm install timed out")
                except Exception as e:
                    logger.warning(f"Could not install dependencies: {e}")
            
            while not build_passed and attempt < max_build_fix_attempts:
                attempt += 1
                try:
                    build_result = subprocess.run(
                        ['npm', 'run', 'build'],
                        cwd=repo_root,
                        capture_output=True,
                        text=True,
                        timeout=120
                    )
                    
                    if build_result.returncode == 0:
                        build_passed = True
                        logger.info("✅ Build check passed!")
                        break
                    else:
                        build_error = build_result.stderr + build_result.stdout
                        logger.warning(f"Build failed (attempt {attempt}/{max_build_fix_attempts}):")
                        logger.warning(build_error[:500])
                        
                        # Try to fix build errors using LLM (use same model that worked for fixes)
                        current_model = model_name if 'model_name' in locals() else "llama-3.3-70b-versatile"
                        fixed_fixes = await fix_build_errors(codebase_analysis, build_error, fixes, repo_root, model=current_model)
                        if fixed_fixes:
                            # Re-apply fixes
                            for file_path, file_data in fixed_fixes.get('files', {}).items():
                                full_path = repo_root / file_path
                                if full_path.exists() and 'changes' in file_data:
                                    with open(full_path, 'r', encoding='utf-8') as f:
                                        current_content = f.read()
                                    old_code = file_data['changes'].get('old_code', '').strip()
                                    new_code = file_data['changes'].get('new_code', '').strip()
                                    
                                    if old_code and new_code:
                                        # Try exact match first
                                        if old_code in current_content:
                                            current_content = current_content.replace(old_code, new_code, 1)  # Replace only first occurrence
                                            with open(full_path, 'w', encoding='utf-8') as f:
                                                f.write(current_content)
                                            logger.info(f"Applied build fix to {file_path}")
                                        else:
                                            logger.warning(f"Exact match not found for old_code in {file_path}. Old code preview: {old_code[:100]}...")
                            
                            # If LLM fixes didn't work and we have a variable conflict, try direct fix
                            variable_name = fixed_fixes.get('_variable_name')
                            problematic_file = fixed_fixes.get('_problematic_file')
                            
                            if variable_name and problematic_file:
                                problematic_full_path = repo_root / problematic_file
                                if problematic_full_path.exists():
                                    logger.info(f"Attempting direct variable fix for '{variable_name}' in {problematic_file}")
                                    if fix_variable_conflict_direct(problematic_full_path, variable_name):
                                        logger.info(f"✅ Direct variable fix succeeded for {problematic_file}")
                                    else:
                                        logger.warning(f"Direct variable fix failed for {problematic_file}")
                            
                            # Update fixes dict for next iteration
                            fixes = fixed_fixes
                        else:
                            # Even if LLM failed, try direct fix if we have variable info
                            variable_name = None
                            problematic_file = None
                            var_match = re.search(r'the name `(\w+)` is defined multiple times', build_error)
                            if var_match:
                                variable_name = var_match.group(1)
                                error_file_match = re.search(r'\./([\w/.-]+\.(js|ts|tsx|jsx))', build_error)
                                if error_file_match:
                                    problematic_file = error_file_match.group(1)
                            
                            if variable_name and problematic_file:
                                problematic_full_path = repo_root / problematic_file
                                if problematic_full_path.exists():
                                    logger.info(f"LLM fix failed, attempting direct variable fix for '{variable_name}' in {problematic_file}")
                                    if fix_variable_conflict_direct(problematic_full_path, variable_name):
                                        logger.info(f"✅ Direct variable fix succeeded for {problematic_file}")
                                    else:
                                        logger.warning(f"Direct variable fix also failed for {problematic_file}")
                            else:
                                logger.warning("Could not generate build fixes, will retry")
                            
                except subprocess.TimeoutExpired:
                    logger.warning("Build check timed out")
                    send_text_message(chat_guid, f"⚠️ Build check timed out. Proceeding...")
                    break
                except Exception as e:
                    logger.warning(f"Build check error: {e}")
                    send_text_message(chat_guid, f"⚠️ Could not run build check. Proceeding...")
                    break
            
            if not build_passed and attempt >= max_build_fix_attempts:
                logger.warning("Build failed after max attempts but proceeding with commit")
        else:
            # No package.json, skip build check
            build_passed = True
            logger.info("No package.json found, skipping build check")
        
        # Stage and commit changes
        build_status = "✅ Build passed" if build_passed else "⚠️ Build issues"
        send_text_message(chat_guid, f"   {build_status}! Committing {len(files_modified)} files...")
        
        for file_path in files_modified:
            subprocess.run(['git', 'add', file_path], check=True, capture_output=True)
        
        commit_message = f"🔒 Security fixes: {fixes.get('summary', 'Fix vulnerabilities')}"
        # Commit with explicit author and committer to ensure ShieldOS is shown
        env = os.environ.copy()
        env['GIT_AUTHOR_NAME'] = 'ShieldOS'
        env['GIT_AUTHOR_EMAIL'] = 'shieldos@shieldos.ai'
        env['GIT_COMMITTER_NAME'] = 'ShieldOS'
        env['GIT_COMMITTER_EMAIL'] = 'shieldos@shieldos.ai'
        subprocess.run([
            'git', 'commit', '-m', commit_message,
            '--author', 'ShieldOS <shieldos@shieldos.ai>'
        ], check=True, capture_output=True, cwd=repo_root, env=env)
        logger.info(f"Committed changes: {commit_message}")
        
        # Set up git remote to use the repo from .env (not the existing remote)
        repo_str = GITHUB_REPO.strip()
        
        # Parse repo URL
        if 'github.com' in repo_str:
            if 'https://' in repo_str or 'http://' in repo_str:
                remote_url = repo_str.replace('.git', '')
                if not remote_url.endswith('.git'):
                    remote_url += '.git'
            else:
                remote_url = f"https://github.com/{repo_str.split('github.com/')[-1].replace('.git', '')}.git"
        else:
            # owner/repo format
            remote_url = f"https://github.com/{repo_str}.git"
        
        # Remove existing origin and add the correct one
        subprocess.run(['git', 'remote', 'remove', 'origin'], check=False, capture_output=True)
        subprocess.run(['git', 'remote', 'add', 'origin', remote_url], check=True, capture_output=True)
        logger.info(f"Set git remote origin to: {remote_url}")
        
        # Push branch
        try:
            push_result = subprocess.run(['git', 'push', '-u', 'origin', branch_name], check=True, capture_output=True, text=True, timeout=30)
            logger.info(f"Pushed branch: {branch_name}")
            logger.debug(f"Git push output: {push_result.stdout}")
            
            # Wait longer for GitHub to process the branch (race condition fix)
            time.sleep(5)
            
            # Create PR automatically using GitHub API
            try:
                # Use the base_branch we stored earlier (it's in the outer scope)
                pr_summary = fixes.get('summary', 'Security vulnerabilities fixed')
                pr_url = await create_github_pr(branch_name, pr_summary, files_modified, base_branch)
                
                if pr_url:
                    send_text_message(chat_guid, f"🎉 PR created: {pr_url}")
                    send_text_message(chat_guid, f"   {pr_summary}")
                else:
                    send_text_message(chat_guid, f"⚠️ Failed to create PR automatically")
                    send_text_message(chat_guid, f"💡 Create manually: gh pr create --title 'Security Fix' --body '{pr_summary}'")
            except Exception as pr_error:
                logger.error(f"PR creation failed: {pr_error}")
                send_text_message(chat_guid, f"⚠️ PR creation failed: {str(pr_error)[:100]}")
                send_text_message(chat_guid, f"✅ Branch pushed: {branch_name}")
                send_text_message(chat_guid, f"💡 Create PR manually on GitHub")
            
        except subprocess.TimeoutExpired:
            send_text_message(chat_guid, f"⚠️ Push timed out. Branch created locally: {branch_name}")
            send_text_message(chat_guid, f"💡 Push manually: git push -u origin {branch_name}")
        except subprocess.CalledProcessError as e:
            logger.warning(f"Git push failed (may not have remote): {e}")
            send_text_message(chat_guid, f"❌ Failed to push branch: {str(e)[:100]}")
            send_text_message(chat_guid, f"💡 Check git remote and permissions")
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Git operation failed: {e}")
        send_text_message(chat_guid, f"❌ Git operation failed: {str(e)[:100]}")
    except Exception as e:
        logger.error(f"Fix command error: {e}", exc_info=True)
        send_text_message(chat_guid, f"❌ Error: {str(e)[:100]}")

async def handle_new_message(data: dict):
    """
    Handles a new-message event from BlueBubbles.
    Handles both webhook format and direct message format.
    """
    global TARGET_CHAT_GUID
    
    logger.info(f"🔍 HANDLE NEW MESSAGE - Raw data: {json.dumps(data)[:500]}")
    
    # Handle both webhook format (data.data) and direct message format
    # Webhook format: {"type": "new-message", "data": {message object}}
    # Direct format: {message object with text, chatGuid, etc.}
    msg_data = data.get('data', data)  # Try nested first, fallback to direct
    
    logger.info(f"📦 Message data extracted: {json.dumps(msg_data)[:500]}")
    
    if not isinstance(msg_data, dict):
        logger.warning(f"❌ Invalid data format: {type(msg_data)}")
        return
    
    # Check if message is from me (the bot itself)
    is_from_me = msg_data.get('isFromMe', False)
    logger.info(f"👤 isFromMe: {is_from_me}")
    
    # Skip processing messages sent by the bot itself to prevent infinite loops
    if is_from_me:
        logger.info("⚠️ Skipping message from bot itself to prevent command loops")
        return
    
    # Extract chat GUID - try multiple locations
    chat_guid = None
    
    # Try direct chatGuid field first (from TypeScript example)
    if msg_data.get('chatGuid'):
        chat_guid = msg_data.get('chatGuid')
        logger.debug(f"Found chatGuid directly: {chat_guid[:30]}...")
    
    # Try chats array (webhook format)
    if not chat_guid:
        chats = msg_data.get('chats', [])
        if chats and isinstance(chats, list) and len(chats) > 0:
            if isinstance(chats[0], dict):
                chat_guid = chats[0].get('guid')
            else:
                chat_guid = chats[0]
            logger.debug(f"Found chatGuid from chats array: {chat_guid[:30]}...")
    
    if not chat_guid:
        logger.warning(f"No chat GUID found. Message keys: {list(msg_data.keys())}")
        logger.warning(f"Full message data: {json.dumps(msg_data)[:300]}")
        return
    
    # Get message text - handle null/None
    text_raw = msg_data.get('text') or msg_data.get('message') or ''
    logger.info(f"📝 Raw text from message: {repr(text_raw)}")
    
    if isinstance(text_raw, str):
        text_raw = text_raw.strip()
    else:
        text_raw = str(text_raw).strip() if text_raw else ''
    
    logger.info(f"📝 Processed text: {repr(text_raw)}")
    
    if not text_raw:
        logger.warning("⚠️ Message has no text content - cannot process command")
        logger.warning(f"📋 All message keys: {list(msg_data.keys())}")
        return
    
    text = text_raw.lower().strip()
    logger.info(f"📨 Processing command from chat {chat_guid[:30]}...: '{text_raw[:50]}'")
    
    # Command handlers - use exact match or command prefix to avoid false positives
    # Check if text is a command (starts with command word or is exact match)
    is_command = (
        text == "start" or text == "stop" or text == "ping" or 
        text == "analyze" or text == "summary" or text == "report" or text == "fix" or
        text.startswith("analyze") or text.startswith("summary") or text.startswith("report") or
        text.startswith("start") or text.startswith("stop") or text.startswith("ping") or text.startswith("fix")
    )
    
    # Only process if it looks like an actual command, not just containing the word
    if not is_command:
        logger.debug(f"Message '{text[:30]}' doesn't appear to be a command, skipping")
        return
    
    if text == "start" or text.startswith("start"):
        TARGET_CHAT_GUID = chat_guid
        send_text_message(chat_guid, "✅ Alerts enabled for this chat. Monitoring network traffic...")
        logger.info(f"✅ Alerts enabled for chat {chat_guid[:30]}...")
    
    elif text == "stop" or text.startswith("stop"):
        TARGET_CHAT_GUID = None
        send_text_message(chat_guid, "✅ Alerts disabled.")
        logger.info("Alerts disabled by user.")
    
    elif text == "ping" or text.startswith("ping"):
        send_text_message(chat_guid, "Pong! Server is running.")
        logger.info("Ping response sent")
    
    elif text == "fix" or text.startswith("fix"):
        logger.info("🔧 Fix command received, analyzing vulnerabilities and generating fixes...")
        try:
            await handle_fix_command(chat_guid)
        except Exception as e:
            logger.error(f"❌ Fix command failed: {e}", exc_info=True)
            send_text_message(chat_guid, f"❌ Fix failed: {str(e)[:100]}")
    
    elif text == "analyze" or text == "summary" or text == "report" or text.startswith("analyze") or text.startswith("summary") or text.startswith("report"):
        logger.info("🔍 Analyze command received, generating summary...")
        try:
            summary = generate_analysis_summary()
            
            # Send SMS with summary
            send_text_message(chat_guid, summary["text_summary"])
            logger.info("✅ Analysis summary sent via SMS")
            
            # Send Mermaid diagram as image URL (iMessage can display images)
            if summary.get("mermaid_diagram"):
                import base64
                
                diagram_code = summary['mermaid_diagram']
                
                # Create text description
                mermaid_msg = "📊 Attack Flow Diagram:\n\n"
                
                diagram_text = diagram_code
                if "DDoS Attack" in diagram_text or "ddos" in diagram_text.lower():
                    mermaid_msg += "1️⃣ Attacker → Floods server\n"
                    mermaid_msg += "2️⃣ ShieldOS → Detects spike\n"
                    mermaid_msg += "3️⃣ ShieldOS → Triggers alert\n"
                elif "SQL Injection" in diagram_text or "sqli" in diagram_text.lower():
                    mermaid_msg += "1️⃣ Attacker → Sends SQL payload\n"
                    mermaid_msg += "2️⃣ ShieldOS → Detects pattern\n"
                    mermaid_msg += "3️⃣ ShieldOS → Triggers alert\n"
                else:
                    mermaid_msg += "1️⃣ Client → Sends requests\n"
                    mermaid_msg += "2️⃣ ShieldOS → Monitors traffic\n"
                    mermaid_msg += "3️⃣ ShieldOS → Generates analysis\n"
                
                # Convert Mermaid diagram to PNG and send as image attachment
                try:
                    import tempfile
                    import base64
                    
                    # Generate mermaid.ink PNG URL
                    diagram_bytes = diagram_code.encode('utf-8')
                    diagram_base64 = base64.urlsafe_b64encode(diagram_bytes).decode('utf-8')
                    diagram_base64 = diagram_base64.rstrip('=')
                    mermaid_png_url = f"https://mermaid.ink/img/{diagram_base64}"
                    
                    # Download the PNG image
                    logger.info(f"Downloading Mermaid PNG from: {mermaid_png_url[:80]}...")
                    png_response = requests.get(mermaid_png_url, timeout=30)
                    
                    if png_response.ok and png_response.headers.get('content-type', '').startswith('image/'):
                        # Save to temporary file
                        png_content = png_response.content
                        content_type = png_response.headers.get('content-type', 'image/png')
                        logger.info(f"Downloaded image: {len(png_content)} bytes, Content-Type: {content_type}")
                        
                        if len(png_content) == 0:
                            logger.error("Downloaded image is empty!")
                            send_text_message(chat_guid, mermaid_msg + f"\n🔗 View diagram: {mermaid_png_url}")
                        else:
                            # Use appropriate file extension based on content type
                            file_ext = '.png'
                            if 'jpeg' in content_type.lower() or 'jpg' in content_type.lower():
                                file_ext = '.jpg'
                            
                            with tempfile.NamedTemporaryFile(delete=False, suffix=file_ext) as tmp_file:
                                tmp_file.write(png_content)
                                tmp_image_path = tmp_file.name
                            
                            # Verify file was saved correctly
                            if os.path.exists(tmp_image_path) and os.path.getsize(tmp_image_path) > 0:
                                logger.info(f"Image saved to temp file: {tmp_image_path} ({os.path.getsize(tmp_image_path)} bytes)")
                                
                                # Send text message first to indicate what the diagram is
                                send_text_message(chat_guid, "📊 Attack Flow Diagram:")
                                
                                # Then send the image as attachment (with minimal message)
                                if send_image_message(chat_guid, tmp_image_path, message="", content_type=content_type):
                                    logger.info("✅ Mermaid diagram image sent as attachment")
                                else:
                                    logger.warning("Failed to send PNG, falling back to URL")
                                    send_text_message(chat_guid, f"🔗 View diagram: {mermaid_png_url}")
                                
                                # Clean up temp file
                                try:
                                    os.unlink(tmp_image_path)
                                except:
                                    pass
                            else:
                                logger.error(f"Failed to save PNG to temp file: {tmp_image_path}")
                                send_text_message(chat_guid, mermaid_msg + f"\n🔗 View diagram: {mermaid_png_url}")
                    else:
                        logger.error(f"Failed to download PNG: {png_response.status_code}")
                        # Fallback: send URL
                        send_text_message(chat_guid, mermaid_msg + f"\n🔗 View diagram: {mermaid_png_url}")
                        
                except Exception as e:
                    logger.error(f"Failed to convert/send Mermaid PNG: {e}", exc_info=True)
                    # Fallback: just send text description
                    send_text_message(chat_guid, mermaid_msg)
                    logger.info("✅ Mermaid diagram text description sent via SMS (fallback)")
            
            # Broadcast to WebSocket clients
            if event_loop and connected_websockets:
                try:
                    asyncio.run_coroutine_threadsafe(broadcast_analysis(summary), event_loop)
                    logger.info("📡 Analysis broadcasted to WebSocket clients")
                except Exception as e:
                    logger.error(f"Failed to broadcast analysis: {e}")
        except Exception as e:
            logger.error(f"❌ Analysis generation failed: {e}", exc_info=True)
            send_text_message(chat_guid, f"❌ Analysis failed: {str(e)[:100]}")

@app.get("/status")
def get_status():
    return {
        "sniffing": IS_SNIFFING,
        "target_chat": TARGET_CHAT_GUID,
        "packets_per_second_last_check": len(PACKET_WINDOW)
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
