# Web Application Firewall (WAF) for Flask

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/flask-2.0+-lightgrey.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

A lightweight, open-source Web Application Firewall designed specifically for Flask applications. Provides real-time protection against common web threats with minimal performance overhead.

## Features

- **Attack Detection**: Regex-based pattern matching for:
  - SQL Injection (e.g., `' OR 1=1 --`)
  - Cross-Site Scripting (XSS) (e.g., `<script>alert()</script>`)
  - Path Traversal (e.g., `../../../etc/passwd`)
  - Command Injection (e.g., `; rm -rf /`)

- **IP Reputation System**:
  - Tracks malicious activity per IP address
  - Automatic blocking of repeat offenders
  - Whitelist/blacklist management

- **Real-time Monitoring**:
  - Detailed logging to file and database
  - Rotating log files (1MB max, 5 backups)
  - SQLite storage for blocked requests

- **Rate Limiting**:
  - Prevents brute-force attacks
  - Configurable thresholds (default: 50 requests/hour)
  - IP-based tracking
