import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Search, AlertTriangle, CheckCircle, XCircle, Info } from 'lucide-react';
import ThreatMeter from './ThreatMeter';
import './Components.css';

const URLScanner = () => {
  const [url, setUrl] = useState('');
  const [scanResult, setScanResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const scanURL = async () => {
    if (!url) return;
    
    setLoading(true);
    try {
      const response = await fetch('http://localhost:8000/scan/url', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url }),
      });
      
      const result = await response.json();
      setScanResult(result);
    } catch (error) {
      console.error('Scan failed:', error);
      alert('Scan failed. Make sure backend is running on port 8000.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="scanner-container">
      {/* Scanner Card */}
      <motion.div 
        className="scanner-card glass-effect"
        initial={{ scale: 0.95 }}
        animate={{ scale: 1 }}
        transition={{ duration: 0.5 }}
      >
        <h2 className="scanner-title cyber-font">
          <Search size={24} />
          URL THREAT ANALYSIS
        </h2>
        
        <div className="input-group">
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="Enter URL to analyze (e.g., https://example.com)"
            className="url-input"
          />
          <button
            onClick={scanURL}
            disabled={loading || !url}
            className="scan-button"
          >
            {loading ? (
              <>
                <div className="loading-spinner"></div>
                <span>SCANNING...</span>
              </>
            ) : (
              <>
                <Search size={16} />
                <span>SCAN URL</span>
              </>
            )}
          </button>
        </div>

        {/* Tips Box */}
        <div className="tips-box">
          <div className="tips-header">
            <Info size={16} />
            <h3>DETECTION FEATURES:</h3>
          </div>
          <ul className="tips-list">
            <li>URL Structure Analysis & Suspicious Pattern Detection</li>
            <li>Phishing Keyword Identification & Domain Reputation</li>
            <li>Threat Intelligence Integration & Real-time Scoring</li>
          </ul>
        </div>
      </motion.div>

      {/* Results */}
      {scanResult && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="results-card glass-effect"
        >
          <div className="results-grid">
            {/* Threat Meter */}
            <div className="threat-meter-section">
              <ThreatMeter score={scanResult.threat_score} />
            </div>

            {/* Analysis Details */}
            <div className="analysis-details">
              <div className="results-header">
                <h3 className="cyber-font">ANALYSIS REPORT</h3>
                <div className={`status-badge ${scanResult.is_malicious ? 'malicious' : 'safe'}`}>
                  {scanResult.is_malicious ? (
                    <>
                      <AlertTriangle size={16} />
                      <span>MALICIOUS</span>
                    </>
                  ) : (
                    <>
                      <CheckCircle size={16} />
                      <span>SAFE</span>
                    </>
                  )}
                </div>
              </div>

              {/* URL Display */}
              <div className="url-display">
                <p className="url-label">SCANNED URL</p>
                <p className="url-value">{scanResult.url}</p>
              </div>

              {/* Threat Reasons */}
              {scanResult.reasons.length > 0 && (
                <div className="threats-section">
                  <h4 className="section-title cyber-font">DETECTED THREATS</h4>
                  <div className="threats-list">
                    {scanResult.reasons.map((reason, index) => (
                      <div key={index} className="threat-item">
                        <XCircle size={16} className="threat-icon" />
                        <p className="threat-text">{reason}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Technical Details */}
              <div className="technical-section">
                <h4 className="section-title cyber-font">TECHNICAL ANALYSIS</h4>
                <div className="tech-grid">
                  {Object.entries(scanResult.details).map(([key, value]) => (
                    <div key={key} className="tech-item">
                      <p className="tech-label">{key.replace('_', ' ')}</p>
                      <p className="tech-value">
                        {Array.isArray(value) ? value.join(', ') : value.toString()}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </motion.div>
      )}
    </div>
  );
};

export default URLScanner;