import React from 'react';
import { motion } from 'framer-motion';
import './Components.css';

const ThreatMeter = ({ score }) => {
  const getThreatLevel = (score) => {
    if (score < 30) return { level: 'LOW', color: '#00ff41' };
    if (score < 70) return { level: 'MEDIUM', color: '#fbbf24' };
    return { level: 'HIGH', color: '#ff073a' };
  };

  const { level, color } = getThreatLevel(score);

  return (
    <div className="threat-meter">
      <h3 className="meter-title cyber-font">THREAT METER</h3>
      
      <div className="gauge-container">
        <svg viewBox="0 0 120 120" className="gauge-svg">
          {/* Background circle */}
          <circle
            cx="60"
            cy="60"
            r="54"
            fill="none"
            stroke="#1a1a1a"
            strokeWidth="8"
          />
          
          {/* Progress circle */}
          <motion.circle
            cx="60"
            cy="60"
            r="54"
            fill="none"
            stroke={color}
            strokeWidth="8"
            strokeLinecap="round"
            initial={{ pathLength: 0 }}
            animate={{ pathLength: score / 100 }}
            transition={{ duration: 1, ease: "easeOut" }}
            transform="rotate(-90 60 60)"
          />
        </svg>
        
        <motion.div
          className="score-text"
          initial={{ scale: 0 }}
          animate={{ scale: 1 }}
          transition={{ delay: 0.5, type: "spring", stiffness: 200 }}
        >
          {score}
        </motion.div>
      </div>
      
      <div className="level-text" style={{ color }}>
        {level}
      </div>
      
      <div className="threat-indicators">
        <span>SAFE</span>
        <span>RISKY</span>
        <span>DANGER</span>
      </div>
    </div>
  );
};

export default ThreatMeter;