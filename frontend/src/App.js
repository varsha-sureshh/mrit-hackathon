import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, Smartphone, History, Zap } from 'lucide-react';
import URLScanner from './components/URLScanner';
import MobileScanner from './components/MobileScanner';
import HistoryPanel from './components/HistoryPanel';
import './App.css';

function App() {
  const [activeTab, setActiveTab] = useState('url');

  const tabs = [
    { id: 'url', name: 'URL Scanner', icon: Shield },
    { id: 'mobile', name: 'Mobile Scan', icon: Smartphone },
    { id: 'history', name: 'History', icon: History },
  ];

  return (
    <div className="app-container">
      {/* Header */}
      <header className="header glass-effect">
        <div className="header-content">
          <div className="logo">
            <div className="logo-icon cyber-glow">
              <Shield size={32} color="#0a0a0a" />
            </div>
            <div className="logo-text">
              <h1 className="cyber-font">CYBER GUARD</h1>
              <p>Advanced Threat Detection System</p>
            </div>
          </div>
          
          <div className="status-indicator">
            <Zap size={16} />
            <span className="cyber-font">SYSTEM ACTIVE</span>
            <div className="pulse-dot"></div>
          </div>
        </div>
      </header>

      {/* Navigation */}
      <nav className="navigation glass-effect">
        <div className="nav-container">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`nav-button ${activeTab === tab.id ? 'active' : ''}`}
              >
                <Icon size={16} />
                <span>{tab.name}</span>
              </button>
            );
          })}
        </div>
      </nav>

      {/* Main Content */}
      <main className="main-content">
        <AnimatePresence mode="wait">
          <motion.div
            key={activeTab}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            transition={{ duration: 0.3 }}
          >
            {activeTab === 'url' && <URLScanner />}
            {activeTab === 'mobile' && <MobileScanner />}
            {activeTab === 'history' && <HistoryPanel />}
          </motion.div>
        </AnimatePresence>
      </main>
    </div>
  );
}

export default App;