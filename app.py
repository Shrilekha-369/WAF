from flask import Flask, request, abort, jsonify, render_template, redirect, url_for, flash
import re
import logging
import sqlite3
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import hashlib
import secrets
from functools import wraps
import ipaddress
from logging.handlers import RotatingFileHandler

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Secure secret key for sessions

# Enhanced rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# Logging setup with rotation
import logging
from logging.handlers import RotatingFileHandler

# Proper logging setup with rotation
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler(
            'firewall.log',
            maxBytes=1000000,  # 1MB per file
            backupCount=5,    # Keep 5 backup files
            encoding='utf-8'
        ),
        logging.StreamHandler()  # Also log to console
    ]
)

# Database setup with more tables
def init_db():
    conn = sqlite3.connect('firewall.db')
    cursor = conn.cursor()
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS blocked_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT,
                    request_data TEXT,
                    timestamp DATETIME,
                    attack_type TEXT,
                    user_agent TEXT)''')
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS ip_reputation (
                    ip TEXT PRIMARY KEY,
                    score INTEGER DEFAULT 0,
                    last_updated DATETIME)''')
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS allowed_ips (
                    ip TEXT PRIMARY KEY,
                    description TEXT)''')
    
    conn.commit()
    conn.close()

init_db()

# Enhanced blacklist patterns with more attack vectors
blacklist_patterns = {
    'SQL Injection': [
        r"(union.*select.*from)",
        r"(drop\s+table)",
        r"(or\s+1=1)",
        r"(;\s*--\s*)",
        r"(exec\(|execute\()",
        r"(insert\s+into.*values)",
        r"(delete\s+from)",
    ],
    'XSS Attack': [
        r"(<script.*?>.*?</script>)",
        r"(javascript:)",
        r"(onerror\s*=\s*)",
        r"(onload\s*=\s*)",
        r"(alert\()",
    ],
    'Path Traversal': [
        r"(\.\./)",
        r"(\.\.\\)",
        r"(etc/passwd)",
        r"(boot\.ini)",
    ],
    'Command Injection': [
        r"(\|\s*sh\s*)",
        r"(\|\s*bash\s*)",
        r"(;\s*rm\s+-)",
        r"(wget\s+)",
        r"(curl\s+)",
    ],
    'Other': [
        r"(<\?php)",
        r"(\.\./\.\./)",
        r"(\\x[0-9a-f]{2})",  # Hex encoding
        r"(%[0-9a-f]{2})",    # URL encoding
    ]
}

# IP reputation management
def update_ip_reputation(ip, penalty=10):
    conn = sqlite3.connect('firewall.db')
    cursor = conn.cursor()
    
    cursor.execute("SELECT score FROM ip_reputation WHERE ip=?", (ip,))
    result = cursor.fetchone()
    
    if result:
        new_score = result[0] + penalty
        cursor.execute("UPDATE ip_reputation SET score=?, last_updated=? WHERE ip=?", 
                      (new_score, datetime.now(), ip))
    else:
        cursor.execute("INSERT INTO ip_reputation (ip, score, last_updated) VALUES (?, ?, ?)", 
                      (ip, penalty, datetime.now()))
    
    conn.commit()
    conn.close()

def get_ip_reputation(ip):
    conn = sqlite3.connect('firewall.db')
    cursor = conn.cursor()
    cursor.execute("SELECT score FROM ip_reputation WHERE ip=?", (ip,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else 0

# Check if IP is in allowed list
def is_ip_allowed(ip):
    conn = sqlite3.connect('firewall.db')
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM allowed_ips WHERE ip=?", (ip,))
    result = cursor.fetchone()
    conn.close()
    return result is not None

# Enhanced malicious request detection
def detect_attack_type(data):
    for attack_type, patterns in blacklist_patterns.items():
        for pattern in patterns:
            if re.search(pattern, data, re.IGNORECASE):
                return attack_type
    return "Unknown"

def is_malicious_request(data):
    for patterns in blacklist_patterns.values():
        for pattern in patterns:
            if re.search(pattern, data, re.IGNORECASE):
                return True
    return False

# Request sanitization
def sanitize_input(data):
    if isinstance(data, str):
        # Basic sanitization - in production use proper sanitization libraries
        data = data.replace('<', '&lt;').replace('>', '&gt;')
        data = data.replace("'", "''")
    return data

# Admin authentication decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # In production, use proper authentication like Flask-Login
        if not request.args.get('admin_token') == app.secret_key:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def firewall():
    client_ip = request.remote_addr
    
    # Skip firewall for allowed IPs
    if is_ip_allowed(client_ip):
        return
    
    # Check IP reputation
    if get_ip_reputation(client_ip) > 50:  # Threshold for automatic blocking
        log_and_block(client_ip, "High reputation score", "IP Reputation")
    
    # Check request data
    for source in [request.args, request.form, request.headers]:
        for key, value in source.items():
            if isinstance(value, str) and is_malicious_request(value):
                attack_type = detect_attack_type(value)
                log_and_block(client_ip, f"{key}={value}", attack_type)
    
    # Check for suspicious user agents
    user_agent = request.headers.get('User-Agent', '')
    if not user_agent or "Mozilla" not in user_agent:
        log_and_block(client_ip, f"Suspicious User-Agent: {user_agent}", "Suspicious User-Agent")

def log_and_block(ip, data, attack_type):
    user_agent = request.headers.get('User-Agent', 'Unknown')
    
    # Update IP reputation
    update_ip_reputation(ip)
    
    # Log to file
    logging.warning(f'Blocked {attack_type} from {ip}: {data[:200]}')
    
    # Store in database
    conn = sqlite3.connect('firewall.db')
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO blocked_requests (ip, request_data, timestamp, attack_type, user_agent) 
        VALUES (?, ?, ?, ?, ?)
    """, (ip, data[:1000], datetime.now(), attack_type, user_agent[:200]))
    conn.commit()
    conn.close()
    
    # Return fake 404 to avoid revealing security measures
    abort(404, description="Page not found")


def get_recent_activity(ip):
    conn = sqlite3.connect('firewall.db')
    cursor = conn.cursor()
    cursor.execute("""
        SELECT timestamp, attack_type, request_data 
        FROM blocked_requests 
        WHERE ip = ? 
        ORDER BY timestamp DESC 
        LIMIT 5
    """, (ip,))
    results = cursor.fetchall()
    conn.close()
    
    if not results:
        return "No recent activity found"
    
    return "\n".join(
        f"{row[0]} - {row[1]}: {row[2][:100]}{'...' if len(row[2]) > 100 else ''}"
        for row in results
    )

@app.route('/')
def home():
    return "Welcome to the Secure Web Application!"

@app.route('/admin')
@admin_required
def admin():
    conn = sqlite3.connect('firewall.db')
    cursor = conn.cursor()
    
    # Get blocked requests
    cursor.execute("""
        SELECT ip, timestamp, attack_type, request_data, user_agent 
        FROM blocked_requests 
        ORDER BY timestamp DESC 
        LIMIT 100
    """)
    logs = cursor.fetchall()
    
    # Get IP reputation data
    cursor.execute("""
        SELECT ip, score, last_updated 
        FROM ip_reputation 
        ORDER BY score DESC 
        LIMIT 50
    """)
    reputation = cursor.fetchall()
    
    conn.close()
    
    return render_template('admin.html', logs=logs, reputation=reputation)

@app.route('/admin/whitelist', methods=['POST'])
@admin_required
def whitelist_ip():
    ip = request.form.get('ip')
    description = request.form.get('description', '')
    
    try:
        # Validate IP address
        ipaddress.ip_address(ip)
        
        conn = sqlite3.connect('firewall.db')
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO allowed_ips (ip, description)
            VALUES (?, ?)
        """, (ip, description))
        conn.commit()
        conn.close()
        
        flash(f"IP {ip} has been whitelisted", "success")
    except ValueError:
        flash("Invalid IP address", "error")
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
    
    return redirect(url_for('admin'))

if __name__ == '__main__':
    app.run(debug=False, port=8080)