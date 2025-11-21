import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Smartphone, AlertTriangle, CheckCircle, Download, Shield, Wifi, Cpu, UserCheck } from 'lucide-react';
import ThreatMeter from './ThreatMeter';
import './Components.css';

const MobileScanner = () => {
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);

  const startMobileScan = async () => {
    setScanning(true);
    try {
      const response = await fetch('http://localhost:8000/scan/mobile');
      const result = await response.json();
      setScanResult(result);
    } catch (error) {
      console.error('Mobile scan failed:', error);
      alert('Make sure backend is running on port 8000');
    } finally {
      setScanning(false);
    }
  };

  const isErrorResult = scanResult && scanResult.device_id === "error";

  return (
    <div className="scanner-container">
      <motion.div 
        className="scanner-card glass-effect mobile-scanner"
        initial={{ scale: 0.95 }}
        animate={{ scale: 1 }}
      >
        <h2 className="scanner-title cyber-font">
          <Smartphone size={24} />
          MOBILE DEVICE FORENSICS
        </h2>

        <div className="mobile-scanner-grid">
          {/* Scanner Interface */}
          <div className="scanner-interface">
            <div className="connection-status">
              <h3 className="cyber-font">CONNECTION STATUS</h3>
              
              <div className="status-items">
                <div className="status-item">
                  <span>USB Debugging</span>
                  <div className="status-indicators">
                    <div className="status-dot active"></div>
                    <span className="status-text active">READY</span>
                  </div>
                </div>
                
                <div className="status-item">
                  <span>ADB Connection</span>
                  <div className="status-indicators">
                    <div className="status-dot active"></div>
                    <span className="status-text active">CONNECTED</span>
                  </div>
                </div>
              </div>
            </div>

            <button
              onClick={startMobileScan}
              disabled={scanning}
              className="mobile-scan-button"
            >
              {scanning ? (
                <>
                  <div className="loading-spinner"></div>
                  <span>SCANNING DEVICE...</span>
                </>
              ) : (
                <>
                  <Download size={20} />
                  <span>START MOBILE SCAN</span>
                </>
              )}
            </button>
          </div>

          {/* Instructions */}
          <div className="instructions-box">
            <h3 className="cyber-font">SETUP INSTRUCTIONS</h3>
            <ul className="instructions-list">
              <li>Enable Developer Options on Android</li>
              <li>Turn on USB Debugging</li>
              <li>Connect device via USB cable</li>
              <li>Trust this computer when prompted</li>
            </ul>
          </div>
        </div>
      </motion.div>

      {/* Scan Results */}
      {scanResult && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="results-card glass-effect"
        >
          <div className="results-grid">
            <div className="threat-meter-section">
              <ThreatMeter score={scanResult.threat_score} />
            </div>

            <div className="analysis-details">
              {/* Device Information Section */}
              {!isErrorResult && scanResult.scan_details && (
                <div className="device-info-section">
                  <h3 className="cyber-font mobile-results-title">
                    <Smartphone size={20} />
                    DEVICE INFORMATION
                  </h3>
                  <div className="device-info-grid">
                    {scanResult.scan_details.device_model && (
                      <div className="device-info-item">
                        <Cpu size={16} className="device-info-icon" />
                        <div>
                          <p className="device-info-label">Device Model</p>
                          <p className="device-info-value">{scanResult.scan_details.device_model}</p>
                        </div>
                      </div>
                    )}
                    {scanResult.scan_details.android_version && (
                      <div className="device-info-item">
                        <Shield size={16} className="device-info-icon" />
                        <div>
                          <p className="device-info-label">Android Version</p>
                          <p className="device-info-value">{scanResult.scan_details.android_version}</p>
                        </div>
                      </div>
                    )}
                    {scanResult.scan_details.security_patch && (
                      <div className="device-info-item">
                        <UserCheck size={16} className="device-info-icon" />
                        <div>
                          <p className="device-info-label">Security Patch</p>
                          <p className="device-info-value">{scanResult.scan_details.security_patch}</p>
                        </div>
                      </div>
                    )}
                    {scanResult.scan_details.installed_apps && (
                      <div className="device-info-item">
                        <Download size={16} className="device-info-icon" />
                        <div>
                          <p className="device-info-label">Installed Apps</p>
                          <p className="device-info-value">{scanResult.scan_details.installed_apps}</p>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Scan Results Title */}
              <h3 className="cyber-font mobile-results-title" style={{marginTop: '2rem'}}>
                SECURITY ANALYSIS REPORT
              </h3>

              {/* Error State */}
              {isErrorResult ? (
                <div className="error-scan">
                  <AlertTriangle size={64} className="error-icon" />
                  <h4 className="cyber-font error-title">SCAN FAILED</h4>
                  <div className="error-messages">
                    {scanResult.suspicious_items.map((item, index) => (
                      <p key={index} className="error-text">{item}</p>
                    ))}
                  </div>
                </div>
              ) : (
                <>
                  {/* Threat Findings */}
                  {scanResult.suspicious_items.length > 0 ? (
                    <div className="mobile-findings">
                      <h4 className="section-title cyber-font suspicious-title">
                        <AlertTriangle size={20} />
                        SECURITY ISSUES DETECTED
                      </h4>
                      <div className="suspicious-list">
                        {scanResult.suspicious_items.map((item, index) => (
                          <div key={index} className="suspicious-item">
                            <AlertTriangle size={16} className="threat-icon" />
                            <p>{item}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : (
                    <div className="clean-scan">
                      <CheckCircle size={64} className="clean-icon" />
                      <h4 className="cyber-font clean-title">NO THREATS DETECTED</h4>
                      <p className="clean-text">Your device appears to be clean and secure</p>
                    </div>
                  )}

                  {/* Scan Details */}
                  <div className="scan-details">
                    <h4 className="section-title cyber-font">SCAN STATISTICS</h4>
                    <div className="tech-grid">
                      {scanResult.scan_details.installed_apps && (
                        <div className="tech-item">
                          <p className="tech-label">Total Apps Scanned</p>
                          <p className="tech-value">{scanResult.scan_details.installed_apps}</p>
                        </div>
                      )}
                      {scanResult.scan_details.suspicious_apps && (
                        <div className="tech-item">
                          <p className="tech-label">Suspicious Apps</p>
                          <p className="tech-value">{scanResult.scan_details.suspicious_apps.length}</p>
                        </div>
                      )}
                      {scanResult.scan_details.dangerous_permissions && (
                        <div className="tech-item">
                          <p className="tech-label">Dangerous Permissions</p>
                          <p className="tech-value">{scanResult.scan_details.dangerous_permissions.length} found</p>
                        </div>
                      )}
                      {scanResult.scan_details.network_connections && (
                        <div className="tech-item">
                          <p className="tech-label">Network Connections</p>
                          <p className="tech-value">{scanResult.scan_details.network_connections.length} active</p>
                        </div>
                      )}
                      {scanResult.scan_details.scan_type && (
                        <div className="tech-item">
                          <p className="tech-label">Scan Type</p>
                          <p className="tech-value">{scanResult.scan_details.scan_type}</p>
                        </div>
                      )}
                      {scanResult.device_id && scanResult.device_id !== "demo_device" && (
                        <div className="tech-item">
                          <p className="tech-label">Device ID</p>
                          <p className="tech-value">{scanResult.device_id}</p>
                        </div>
                      )}
                    </div>
                  </div>
                </>
              )}
            </div>
          </div>
        </motion.div>
      )}
    </div>
  );
};

export default MobileScanner;