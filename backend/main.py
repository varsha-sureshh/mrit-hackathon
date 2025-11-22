from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sqlite3
import requests
import json
import re
import subprocess
from datetime import datetime
from typing import List, Dict, Any

app = FastAPI(title="Malicious URL Detector", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database setup
def init_db():
    conn = sqlite3.connect('security.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            threat_score INTEGER NOT NULL,
            is_malicious BOOLEAN NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            details TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS mobile_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            threat_score INTEGER NOT NULL,
            suspicious_items TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

init_db()

# Data models
class URLRequest(BaseModel):
    url: str

class URLResponse(BaseModel):
    url: str
    is_malicious: bool
    threat_score: int
    reasons: List[str]
    details: Dict[str, Any]

class MobileScanResponse(BaseModel):
    device_id: str
    threat_score: int
    suspicious_items: List[str]
    scan_details: Dict[str, Any]

# URL Analysis Engine
class URLAnalyzer:
    def __init__(self):
        self.suspicious_keywords = [
            'login', 'verify', 'account', 'banking', 'paypal', 'security',
            'update', 'confirm', 'password', 'credential', 'admin', 'user','login', 'verify', 'update', 'free', 'bonus', 'reward',
        'secure', 'bank', 'account', 'wallet', 'crypto', "login", "signin", "verify", "verification", "secure", "security",
    "update", "confirm", "validate", "authentication", "account",
    "password", "credential", "support", "helpdesk", "go00gle", "go0gle", "g0ogle", "g00gle"

    # Phishing / urgency
    "urgent", "alert", "warning", "notice", "locked", "suspended",
    "unlock", "confirm-now", "must-update", "act-now",

    # Financial / payment fraud
    "bank", "banking", "wallet", "payment", "payout", "invoice",
    "billing", "refund", "cashback", "claim",

    # Scams (free/giveaway)
    "free", "giveaway", "bonus", "win", "reward", "prize", "gift",
    "coupon", "promo", "lottery",

    # Tech support scam
    "microsoft-support", "apple-support", "google-support",
    "windows-fix", "system-repair", "antivirus", "firewall",
    "malware-removal", "techsupport", "help-center",

    # Obfuscation / redirect patterns
    "click", "link", "redirect", "forward", "continue", "go-to",
    "track", "landing", "download", "installer",

    # Crypto / investment scams
    "crypto", "bitcoin", "eth", "binance", "walletconnect",
    "ledger", "blockchain", "investment", "trading", "forex",

    # Adult / explicit
    "xxx", "adult", "sex", "pornstar", "dating", "escort", "cams",
    "hotgirls", "erotic", "nudes",

    # Malware / piracy distribution
    "crack", "patch", "hack", "keygen", "serial", "nulled",
    "modapk", "torrents", "pirated", "warez",

    # Generic high-risk
    "unofficial", "proxy", "bypass", "fake", "mirror", "unofficial", "proxy", "bypass", "fake", "mirror", "goo00gle", "faceb00k", "paypa1", "amaz0n", "applle", "microsofft", "go000gle", "yaho0", "bingg", "linkediin", "instagrarn", "twltter", "snapchatt", "tiktokk", "reditt", "pinterestt"
        ]
        self.known_malicious_domains = [
            'evil.com', 'phishing.com', 'malware.com'
        ]
    
    def analyze_url(self, url: str) -> URLResponse:
        threats = []
        details = {}
        
        # 1. Check URL length
        if len(url) > 75:
            threats.append("URL is unusually long (common in phishing)")
            details['url_length'] = len(url)
        
        # 2. Check for IP address instead of domain
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        if re.search(ip_pattern, url):
            threats.append("URL contains IP address instead of domain name")
            details['contains_ip'] = True
        
        # 3. Check for suspicious keywords
        found_keywords = [kw for kw in self.suspicious_keywords if kw in url.lower()]
        if found_keywords:
            threats.append(f"Suspicious keywords found: {', '.join(found_keywords)}")
            details['suspicious_keywords'] = found_keywords
        
        # 4. Check for multiple subdomains
        subdomain_count = url.count('.')
        if subdomain_count > 3:
            threats.append("Too many subdomains (potential phishing)")
            details['subdomain_count'] = subdomain_count
        
        # 5. Check for URL shortening services
        shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly']
        if any(shortener in url for shortener in shorteners):
            threats.append("Uses URL shortening service (could hide malicious destination)")
            details['is_shortened'] = True
        
        # 6. Check for known malicious domains
        if any(domain in url for domain in self.known_malicious_domains):
            threats.append("Known malicious domain detected")
            details['known_malicious'] = True
        
        # Calculate threat score (0-100)
        base_score = len(threats) * 15 + len(found_keywords) * 3
        threat_score = min(100, base_score)
        is_malicious = threat_score > 30
        
        # Save to database
        self.save_scan_result(url, threat_score, is_malicious, threats)
        
        return URLResponse(
            url=url,
            is_malicious=is_malicious,
            threat_score=threat_score,
            reasons=threats,
            details=details
        )
    
    def save_scan_result(self, url: str, score: int, malicious: bool, reasons: list):
        conn = sqlite3.connect('security.db')
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO scan_history (url, threat_score, is_malicious, details) VALUES (?, ?, ?, ?)',
            (url, score, malicious, json.dumps(reasons))
        )
        conn.commit()
        conn.close()

# Mobile Analysis Engine
# Mobile Analysis Engine - REAL IMPLEMENTATION
class MobileAnalyzer:
    def scan_device(self) -> MobileScanResponse:
        try:
            suspicious_items = []
            scan_details = {}
            
            # Check if ADB is available
            try:
                adb_check = subprocess.run(['adb', 'version'], capture_output=True, text=True, timeout=10)
                if adb_check.returncode != 0:
                    raise Exception("ADB not found")
            except:
                return self.get_adb_error_response("ADB not installed or not in PATH")
            
            # Check if device is connected
            devices_result = subprocess.run(['adb', 'devices'], capture_output=True, text=True, timeout=10)
            connected_devices = [line for line in devices_result.stdout.split('\n') if 'device' in line and 'offline' not in line]
            
            if len(connected_devices) <= 1:  # First line is header
                return self.get_adb_error_response("No Android device connected via USB. Enable USB debugging.")
            
            device_id = connected_devices[1].split('\t')[0] if len(connected_devices) > 1 else "unknown"
            
            # Start real scanning
            print(f"Scanning device: {device_id}")
            
            # 1. Scan installed apps
            apps_result = self.scan_installed_apps(device_id)
            suspicious_items.extend(apps_result['suspicious'])
            scan_details['installed_apps'] = apps_result['total']
            scan_details['suspicious_apps'] = apps_result['suspicious']
            
            # 2. Scan permissions
            perm_result = self.scan_dangerous_permissions(device_id)
            suspicious_items.extend(perm_result['suspicious'])
            scan_details['dangerous_permissions'] = perm_result['permissions']
            
            # 3. Scan network connections
            network_result = self.scan_network_connections(device_id)
            suspicious_items.extend(network_result['suspicious'])
            scan_details['network_connections'] = network_result['connections']
            
            # 4. Scan system info
            system_info = self.scan_system_info(device_id)
            scan_details.update(system_info)
            
            # Calculate threat score
            threat_score = min(100, len(suspicious_items) * 8)
            
            # Save scan result
            self.save_mobile_scan(device_id, threat_score, suspicious_items)
            
            return MobileScanResponse(
                device_id=device_id,
                threat_score=threat_score,
                suspicious_items=suspicious_items,
                scan_details=scan_details
            )
            
        except subprocess.TimeoutExpired:
            return self.get_adb_error_response("ADB command timeout - device may be unresponsive")
        except Exception as e:
            return self.get_adb_error_response(f"Scan failed: {str(e)}")
    
    def scan_installed_apps(self, device_id):
        """Scan installed apps for suspicious patterns"""
        try:
            # Get all installed apps
            result = subprocess.run([
                'adb', '-s', device_id, 'shell', 'pm', 'list', 'packages', '-f'
            ], capture_output=True, text=True, timeout=30)
            
            apps = result.stdout.split('\n')
            suspicious_apps = []
            suspicious_patterns = [
                'spy', 'track', 'monitor', 'hidden', 'stealth', 'hack',
                'keylogger', 'trojan', 'malware', 'virus', 'root'
            ]
            
            for app_line in apps:
                if not app_line.startswith('package:'):
                    continue
                    
                app_path = app_line.replace('package:', '').strip()
                app_name = app_path.lower()
                
                # Check for suspicious keywords in app path/name
                for pattern in suspicious_patterns:
                    if pattern in app_name:
                        suspicious_apps.append(f"Suspicious app detected: {app_path}")
                        break
            
            return {
                'total': len([a for a in apps if a.startswith('package:')]),
                'suspicious': suspicious_apps
            }
            
        except Exception as e:
            return {'total': 0, 'suspicious': [f"App scan failed: {str(e)}"]}
    
    def scan_dangerous_permissions(self, device_id):
        """Scan for apps with dangerous permissions"""
        try:
            # Get apps with dangerous permissions
            dangerous_perms = [
                'READ_SMS', 'READ_CALL_LOG', 'ACCESS_FINE_LOCATION',
                'CAMERA', 'RECORD_AUDIO', 'READ_CONTACTS', 'READ_EXTERNAL_STORAGE',
                'WRITE_EXTERNAL_STORAGE', 'BODY_SENSORS', 'CALL_PHONE'
            ]
            
            suspicious_perms = []
            all_permissions = []
            
            for perm in dangerous_perms:
                try:
                    result = subprocess.run([
                        'adb', '-s', device_id, 'shell', 'pm', 'list', 'permissions', '-g'
                    ], capture_output=True, text=True, timeout=20)
                    
                    if perm in result.stdout:
                        all_permissions.append(perm)
                        # Check which apps have this permission
                        app_result = subprocess.run([
                            'adb', '-s', device_id, 'shell', 'pm', 'list', 'packages', '-g'
                        ], capture_output=True, text=True, timeout=20)
                        
                        if app_result.stdout:
                            suspicious_perms.append(f"Dangerous permission granted: {perm}")
                            
                except:
                    continue
            
            return {
                'permissions': all_permissions,
                'suspicious': suspicious_perms[:3]  # Limit to top 3
            }
            
        except Exception as e:
            return {'permissions': [], 'suspicious': [f"Permission scan failed: {str(e)}"]}
    
    def scan_network_connections(self, device_id):
        """Scan network connections for suspicious activity"""
        try:
            # Get network connections
            result = subprocess.run([
                'adb', '-s', device_id, 'shell', 'netstat'
            ], capture_output=True, text=True, timeout=15)
            
            connections = []
            suspicious_connections = []
            
            lines = result.stdout.split('\n')
            for line in lines:
                if 'ESTABLISHED' in line or 'LISTEN' in line:
                    connections.append(line.strip())
                    # Check for suspicious ports or patterns
                    if any(port in line for port in ['4444', '1337', '31337']):
                        suspicious_connections.append(f"Suspicious network connection: {line.strip()}")
            
            return {
                'connections': connections[:10],  # Limit output
                'suspicious': suspicious_connections
            }
            
        except Exception as e:
            return {'connections': [], 'suspicious': [f"Network scan failed: {str(e)}"]}
    
    def scan_system_info(self, device_id):
        """Get basic system information"""
        try:
            system_info = {}
            
            # Get Android version
            android_result = subprocess.run([
                'adb', '-s', device_id, 'shell', 'getprop', 'ro.build.version.release'
            ], capture_output=True, text=True, timeout=10)
            system_info['android_version'] = android_result.stdout.strip()
            
            # Get device model
            model_result = subprocess.run([
                'adb', '-s', device_id, 'shell', 'getprop', 'ro.product.model'
            ], capture_output=True, text=True, timeout=10)
            system_info['device_model'] = model_result.stdout.strip()
            
            # Get security patch level
            security_result = subprocess.run([
                'adb', '-s', device_id, 'shell', 'getprop', 'ro.build.version.security_patch'
            ], capture_output=True, text=True, timeout=10)
            system_info['security_patch'] = security_result.stdout.strip()
            
            return system_info
            
        except Exception as e:
            return {'system_info': f"Failed to get system info: {str(e)}"}
    
    def get_adb_error_response(self, error_message):
        """Return error response when ADB fails"""
        return MobileScanResponse(
            device_id="error",
            threat_score=0,
            suspicious_items=[error_message, "Please ensure:", "1. USB debugging is enabled", "2. Device is connected via USB", "3. ADB is installed"],
            scan_details={"error": error_message, "scan_type": "Failed - Check Connection"}
        )
    
    def save_mobile_scan(self, device_id: str, score: int, items: list):
        conn = sqlite3.connect('security.db')
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO mobile_scans (device_id, threat_score, suspicious_items) VALUES (?, ?, ?)',
            (device_id, score, json.dumps(items))
        )
        conn.commit()
        conn.close()

# Initialize analyzers
url_analyzer = URLAnalyzer()
mobile_analyzer = MobileAnalyzer()

# API Routes
@app.get("/")
async def root():
    return {"message": "Malicious URL Detector API", "status": "active"}

@app.post("/scan/url", response_model=URLResponse)
async def scan_url(request: URLRequest):
    return url_analyzer.analyze_url(request.url)

@app.get("/scan/mobile", response_model=MobileScanResponse)
async def scan_mobile():
    return mobile_analyzer.scan_device()

@app.get("/history/urls")
async def get_url_history():
    conn = sqlite3.connect('security.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM scan_history ORDER BY timestamp DESC LIMIT 10')
    results = cursor.fetchall()
    conn.close()
    
    history = []
    for row in results:
        history.append({
            "id": row[0],
            "url": row[1],
            "threat_score": row[2],
            "is_malicious": bool(row[3]),
            "timestamp": row[4],
            "details": json.loads(row[5]) if row[5] else []
        })
    
    return {"scan_history": history}

@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)