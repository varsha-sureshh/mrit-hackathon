import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Clock, Shield, AlertTriangle, CheckCircle } from 'lucide-react';
import './Components.css';

const HistoryPanel = () => {
  const [scanHistory, setScanHistory] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchScanHistory();
  }, []);

  const fetchScanHistory = async () => {
    try {
      const response = await fetch('http://localhost:8000/history/urls');
      const data = await response.json();
      setScanHistory(data.scan_history || []);
    } catch (error) {
      console.error('Failed to fetch history:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="history-container">
        <div className="scanner-card glass-effect">
          <div className="loading-history">
            <div className="loading-spinner large"></div>
            <p>Loading scan history...</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="history-container">
      <motion.div 
        className="scanner-card glass-effect"
        initial={{ scale: 0.95 }}
        animate={{ scale: 1 }}
      >
        <h2 className="scanner-title cyber-font">
          <Clock size={24} />
          SCAN HISTORY
        </h2>

        {scanHistory.length === 0 ? (
          <div className="empty-history">
            <Shield size={48} className="empty-icon" />
            <h3>No Scan History</h3>
            <p>Scan some URLs to see your history here</p>
          </div>
        ) : (
          <div className="history-list">
            {scanHistory.map((scan) => (
              <motion.div
                key={scan.id}
                className="history-item glass-effect"
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.3 }}
              >
                <div className="history-item-header">
                  <div className="history-url">
                    <p className="url">{scan.url}</p>
                    <p className="timestamp">{new Date(scan.timestamp).toLocaleString()}</p>
                  </div>
                  <div className={`history-status ${scan.is_malicious ? 'malicious' : 'safe'}`}>
                    {scan.is_malicious ? (
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
                
                <div className="history-details">
                  <div className="threat-score">
                    <span className="score-label">Threat Score:</span>
                    <span className={`score-value ${scan.threat_score > 70 ? 'high' : scan.threat_score > 30 ? 'medium' : 'low'}`}>
                      {scan.threat_score}
                    </span>
                  </div>
                  
                  {scan.details && scan.details.length > 0 && (
                    <div className="history-threats">
                      <p className="threats-label">Detected Issues:</p>
                      <ul className="threats-list">
                        {scan.details.map((threat, index) => (
                          <li key={index}>{threat}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              </motion.div>
            ))}
          </div>
        )}
      </motion.div>
    </div>
  );
};

export default HistoryPanel;