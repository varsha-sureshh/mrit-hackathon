# 🛡️ Cyber Guard - Advanced Malicious URL Detector & Mobile Security Scanner
A comprehensive cybersecurity solution that combines real-time URL threat analysis with advanced mobile device security scanning. Built for the modern digital threat landscape.

---

## 🚀 Features

### 🔍 Smart URL Analysis
- **Real-time Threat Detection** — Analyzes URLs for phishing patterns, suspicious domains, and malicious content  
- **Multi-factor Scoring** — Comprehensive threat scoring from 0-100 with detailed explanations  
- **Pattern Recognition** — Detects IP addresses, URL shorteners, suspicious keywords, and domain anomalies  
- **Historical Tracking** — Maintains complete scan history with timestamps and threat details  

### 📱 Advanced Mobile Security
- **Device Forensics** — Real Android device scanning via ADB  
- **App Analysis** — Scans installed applications for suspicious behavior and malware patterns  
- **Permission Auditing** — Identifies dangerous permissions and security risks  
- **Network Monitoring** — Analyzes active network connections for suspicious activity  
- **System Security** — Checks Android version, security patches, and device integrity  

### 🎨 Cyber-Secure Dashboard
- **Immersive UI** — Dark theme with cyberpunk aesthetics and glowing effects  
- **Real-time Visualizations** — Animated threat meters and interactive charts  
- **Responsive Design** — Works seamlessly across desktop and mobile devices  
- **Professional Reporting** — Detailed security reports with actionable insights  

---
## 🛠️ Tech Stack

### **Frontend**
- React 18 — Modern UI framework with hooks  
- Framer Motion — Smooth animations and transitions  
- Custom CSS — Cyber-themed styling with glass morphism effects  
- Lucide React — Beautiful icons for enhanced UX  

### **Backend**
- FastAPI — High-performance Python web framework  
- SQLAlchemy — Database ORM  
- Pydantic — Data validation  
- Uvicorn — ASGI server  

### **Security & Analysis**
- ADB — Android device communication  
- Regex Pattern Matching — URL structure analysis  
- Threat Intelligence — Custom detection algorithms  
- Real-time Scanning  

---

## 📦 Installation

### **Prerequisites**
- Python 3.13+  
- Node.js 16+  
- Android device with USB debugging enabled  
- ADB installed and configured  

---

### **1. Clone the Repository**
```bash
git clone https://github.com/your-username/cyber-guard.git
cd cyber-guard
```
### **2. Backend Setup**
```bash
cd backend
python -m venv venv
venv\Scripts\activate  # Windows
pip install -r requirements.txt
python main.py
```
### **3. Frontend Setup**
```bash
cd frontend
npm install
npm start
```
### **4. Android Device Setup**
Enable Developer Options on your Android device
Turn on USB Debugging
Connect device via USB cable
Trust the computer when prompted

## 🎯 Usage
### URL Security Scanning
Navigate to the URL Scanner tab
Enter any URL for analysis (e.g., https://example.com)
View real-time threat assessment with detailed explanations
Check threat score and security recommendations

### Mobile Device Scanning
Connect your Android device via USB
Go to the Mobile Scan tab
Click Start Mobile Scan
Review device information, app analysis, and security findings

### History & Reports
Access the History tab to view past scans
Export security reports for documentation
Track security trends over time

## 🚀 Deployment
### **Production Backend**
```bash
cd backend
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```
### **Production Frontend**
```bash
cd frontend
npm run build
# Serve the build folder with your preferred web servercd frontend
npm run build
# Serve the build folder with your preferred web server
```

## 📊 Detection Capabilities
### **URL Threat Detection**
✅ Phishing URL patterns
✅ Suspicious domain names
✅ IP address masking
✅ URL shortening services
✅ Excessive subdomains
✅ Malicious keywords
✅ Known bad domains

### **Mobile Security Analysis**
✅ Suspicious applications
✅ Dangerous permissions
✅ Network security risks
✅ System vulnerability assessment
✅ App behavior analysis
✅ Security patch status

## 📝 License
This project is licensed under the MIT License - see the LICENSE.md file for details.
