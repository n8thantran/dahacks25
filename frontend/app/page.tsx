'use client';

import { useEffect, useState, useRef } from 'react';
import mermaid from 'mermaid';

interface Alert {
  type: string;
  source: string;
  timestamp: string;
  message: string;
}

interface Packet {
  src: string;
  dst: string;
  proto: number;
  len: number;
  timestamp: string;
}

interface AnalysisSummary {
  timestamp: string;
  overview: {
    total_packets: number;
    total_alerts: number;
    time_range_seconds: number;
    packets_per_second: number;
    avg_packet_size: number;
  };
  threats: {
    ddos_count: number;
    sqli_count: number;
    top_threat_sources: Record<string, number>;
  };
  traffic: {
    top_source_ips: Record<string, number>;
    protocols: Record<string, number>;
  };
  llm_analysis?: string;
  mermaid_diagram?: string;
  text_summary: string;
}

interface HttpRequest {
  method: string;
  path: string;
  query: string;
  body?: any;
  headers: Record<string, string>;
  client_ip: string;
  timestamp: string;
  threat_type?: string;
  threat_details?: string;
  url: string;
  blocked?: boolean;
  blocked_by?: string;
}

export default function Home() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [packets, setPackets] = useState<Packet[]>([]);
  const [httpRequests, setHttpRequests] = useState<HttpRequest[]>([]);
  const [connected, setConnected] = useState(false);
  const [phoneNumber, setPhoneNumber] = useState('408-916-7303');
  const [monitoredPort, setMonitoredPort] = useState('8000');
  const [analysis, setAnalysis] = useState<AnalysisSummary | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  // Track if we're on client side to prevent hydration errors
  const [isClient, setIsClient] = useState(false);

  // Initialize Mermaid only on client side
  useEffect(() => {
    setIsClient(true);
    
    // Initialize Mermaid with dark theme
    mermaid.initialize({ 
      startOnLoad: false, // Don't auto-start, we'll trigger manually
      theme: 'dark',
      securityLevel: 'loose',
      themeVariables: {
        primaryColor: '#667eea',
        primaryTextColor: '#fff',
        primaryBorderColor: '#764ba2',
        lineColor: '#667eea',
        secondaryColor: '#1a1a1a',
        tertiaryColor: '#0f0f0f',
        background: '#1a1a1a',
        mainBkg: '#1a1a1a',
        secondBkg: '#0f0f0f',
        textColor: '#e0e0e0',
        fontSize: '14px'
      }
    });
  }, []);

  // Render Mermaid diagram when analysis changes (client-side only)
  const mermaidRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!isClient || !analysis?.mermaid_diagram || !mermaidRef.current) {
      return;
    }

    const element = mermaidRef.current;
    const diagramId = `mermaid-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    // Clear previous content
    element.innerHTML = '';
    
    // Create a unique container for this diagram
    const container = document.createElement('div');
    container.id = diagramId;
    container.className = 'mermaid';
    container.textContent = analysis.mermaid_diagram;
    element.appendChild(container);
    
    // Render the diagram
    mermaid.run({
      nodes: [container],
    }).then(() => {
      console.log('Mermaid diagram rendered successfully');
    }).catch((err) => {
      console.error('Mermaid render error:', err);
      element.innerHTML = '<p className="text-red-400 text-xs">Error rendering diagram</p>';
    });
  }, [analysis?.mermaid_diagram, isClient]);

  // Fetch HTTP requests from backend
  useEffect(() => {
    const fetchRequests = async () => {
      try {
        const res = await fetch('http://localhost:8000/api/requests');
        if (res.ok) {
          const data = await res.json();
          if (data.requests) {
            setHttpRequests(data.requests);
          }
        }
      } catch (e) {
        console.error('Failed to fetch requests:', e);
      }
    };

    // Fetch immediately
    fetchRequests();

    // Then poll every second
    const interval = setInterval(fetchRequests, 1000);

    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const connect = () => {
      const ws = new WebSocket('ws://localhost:8000/ws');
      wsRef.current = ws;

      ws.onopen = () => {
        setConnected(true);
        console.log('Connected to backend');
      };

      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.type === 'init' || data.type === 'update') {
          if (data.alerts) setAlerts(data.alerts);
          if (data.packets) setPackets(data.packets);
        } else if (data.type === 'analysis') {
          if (data.analysis) {
            setAnalysis(data.analysis);
            setAnalyzing(false);
          }
        }
      };

      ws.onclose = () => {
        setConnected(false);
        setTimeout(connect, 3000); // Reconnect
      };
    };

    connect();

    return () => {
      wsRef.current?.close();
    };
  }, []);

  const formatPhoneNumberToChatGuid = (phone: string): string => {
    // Remove all non-digit characters
    const digits = phone.replace(/\D/g, '');
    // Add +1 if not present and format as iMessage chat GUID
    const fullNumber = digits.startsWith('1') ? `+${digits}` : `+1${digits}`;
    return `iMessage;-;${fullNumber}`;
  };

  const handleSetConfig = async () => {
    if (!phoneNumber || !monitoredPort) return;
    
    const chatGuid = formatPhoneNumberToChatGuid(phoneNumber);
    const portToSend = parseInt(monitoredPort);
    
    console.log(`🔧 Sending config - Port: ${portToSend} (from input: "${monitoredPort}")`);
    
    try {
        const requestBody = { 
            chat_guid: chatGuid,
            monitored_port: portToSend
        };
        console.log('🔧 Request body:', JSON.stringify(requestBody));
        
        const res = await fetch('http://localhost:8000/api/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(requestBody)
        });
        
        if (res.ok) {
            const data = await res.json();
            console.log('✅ Config saved successfully:', data);
            alert(`Config saved! Alerts → ${phoneNumber}, Monitoring port ${monitoredPort}`);
        } else {
            const errorText = await res.text();
            console.error('❌ Failed to save config:', errorText);
            alert('Failed to save config');
        }
    } catch (e) {
        console.error('❌ Error saving config:', e);
        alert('Failed to save config');
    }
  };

  const simulateAttack = async (type: 'sqli' | 'ddos') => {
    const targetPort = monitoredPort || '8000';
    const baseUrl = `http://localhost:${targetPort}`;
    
    try {
        // First, notify backend to create alert
        await fetch(`http://localhost:8000/api/simulate-traffic?attack_type=${type}`).catch(() => {});
        
        if (type === 'sqli') {
            console.log('🔴 Launching SQL Injection attack...');
            
            const payloads = [
                { username: "' OR '1'='1", password: "anything" },
                { username: "admin' --", password: "test" },
                { username: "' OR 1=1--", password: "test" },
                { username: "admin' UNION SELECT * FROM users--", password: "test" },
                { username: "1' OR '1' = '1", password: "test" },
            ];
            
            for (const payload of payloads) {
                try {
                    // Send to monitored port (for packet capture by sniffer)
                    await fetch(`${baseUrl}/api/login?username=${encodeURIComponent(payload.username)}&password=${encodeURIComponent(payload.password)}`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(payload)
                    }).catch(() => {});
                    
                    // ALSO send to FastAPI server (port 8000) for middleware detection
                    // This ensures detection works even if monitored port is different
                    if (targetPort !== '8000') {
                        await fetch(`http://localhost:8000/api/login?username=${encodeURIComponent(payload.username)}&password=${encodeURIComponent(payload.password)}`, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(payload)
                        }).catch(() => {});
                    }
                    
                    await new Promise(resolve => setTimeout(resolve, 300));
                } catch (error) {
                    // Expected - just generating traffic
                }
            }
            
            console.log('✅ SQL Injection attack simulated! Check ShieldOS dashboard.');
        } else if (type === 'ddos') {
            console.log('🚀🚀🚀 DDoS attack triggered 🚀🚀🚀');
            console.log('🔴 Launching MASSIVE DDoS attack... Firing 500+ requests NOW!');
            
            const startTime = performance.now();
            let requestCounter = 0;
            const healthUrl = `${baseUrl}/api/health`;
            
            // Step 1: Immediately trigger backend simulation endpoint (guaranteed alert)
            fetch(`http://localhost:8000/api/simulate-traffic?attack_type=ddos`).catch(() => {});
            
            // Step 2: Fire MASSIVE burst of requests as fast as possible
            // Use multiple techniques in parallel to maximize packet generation
            const fastApiUrl = 'http://localhost:8000/api/health';
            
            // Technique 1: Synchronous fetch loop - fire 300 requests immediately
            for (let i = 0; i < 300; i++) {
                const ts = performance.now();
                const unique = `${ts}-${i}-${Math.random().toString(36).substr(2, 5)}`;
                
                // Send to monitored port (for packet capture)
                fetch(`${healthUrl}?ddos=${i}&ts=${ts}&u=${unique}`, {
                    method: 'GET',
                    cache: 'no-store',
                    mode: 'cors',
                    credentials: 'omit',
                    headers: {
                        'Cache-Control': 'no-cache, no-store, must-revalidate',
                        'Pragma': 'no-cache',
                        'X-Request-ID': unique
                    }
                }).catch(() => {});
                
                // ALSO send to FastAPI server (port 8000) for middleware detection
                if (targetPort !== '8000') {
                    fetch(`${fastApiUrl}?ddos=${i}&ts=${ts}&u=${unique}`, {
                        method: 'GET',
                        cache: 'no-store',
                        mode: 'cors',
                        credentials: 'omit',
                        headers: {
                            'Cache-Control': 'no-cache, no-store, must-revalidate',
                            'Pragma': 'no-cache',
                            'X-Request-ID': unique
                        }
                    }).catch(() => {});
                }
                
                requestCounter++;
            }
            
            // Technique 2: XMLHttpRequest burst - 100 more requests
            for (let i = 0; i < 100; i++) {
                try {
                    const xhr = new XMLHttpRequest();
                    xhr.open('GET', `${healthUrl}?xhr=${i}&_=${Date.now()}-${Math.random()}`, true);
                    xhr.timeout = 2000;
                    xhr.withCredentials = false;
                    xhr.send();
                    
                    // Also send to FastAPI server for detection
                    if (targetPort !== '8000') {
                        const xhr2 = new XMLHttpRequest();
                        xhr2.open('GET', `${fastApiUrl}?xhr=${i}&_=${Date.now()}-${Math.random()}`, true);
                        xhr2.timeout = 2000;
                        xhr2.withCredentials = false;
                        xhr2.send();
                    }
                    
                    requestCounter++;
                } catch (e) {}
            }
            
            // Technique 3: Image loading - creates GET requests (100 more)
            for (let i = 0; i < 100; i++) {
                const img = new Image();
                img.src = `${healthUrl}?img=${i}&_=${Date.now()}-${Math.random()}`;
                
                // Also send to FastAPI server for detection
                if (targetPort !== '8000') {
                    const img2 = new Image();
                    img2.src = `${fastApiUrl}?img=${i}&_=${Date.now()}-${Math.random()}`;
                }
                
                requestCounter++;
            }
            
            // Technique 4: Rapid-fire setTimeout burst over next 300ms
            for (let i = 0; i < 50; i++) {
                setTimeout(() => {
                    fetch(`${healthUrl}?rapid=${i}&_=${Date.now()}`, {
                        method: 'GET',
                        cache: 'no-store'
                    }).catch(() => {});
                    
                    // Also send to FastAPI server for detection
                    if (targetPort !== '8000') {
                        fetch(`${fastApiUrl}?rapid=${i}&_=${Date.now()}`, {
                            method: 'GET',
                            cache: 'no-store'
                        }).catch(() => {});
                    }
                    
                    requestCounter++;
                }, i * 6); // 6ms intervals = 50 requests over 300ms
            }
            
            // Technique 5: Link prefetch (if supported)
            for (let i = 0; i < 50; i++) {
                try {
                    const link = document.createElement('link');
                    link.rel = 'prefetch';
                    link.href = `${healthUrl}?prefetch=${i}&_=${Date.now()}`;
                    document.head.appendChild(link);
                    
                    // Also send to FastAPI server for detection
                    if (targetPort !== '8000') {
                        const link2 = document.createElement('link');
                        link2.rel = 'prefetch';
                        link2.href = `${fastApiUrl}?prefetch=${i}&_=${Date.now()}`;
                        document.head.appendChild(link2);
                        setTimeout(() => link2.remove(), 100);
                    }
                    
                    requestCounter++;
                    // Remove immediately to avoid memory issues
                    setTimeout(() => link.remove(), 100);
                } catch (e) {}
            }
            
            console.log(`Fired ${requestCounter} requests immediately`);
            
            // Update status after a moment
            setTimeout(() => {
                const elapsed = ((performance.now() - startTime) / 1000).toFixed(2);
                console.log(`✅ DDoS complete: ~${requestCounter} requests in ${elapsed}s`);
                console.log(`✅ DDoS attack complete! ~${requestCounter} requests fired in ${elapsed}s. Check ShieldOS dashboard!`);
            }, 800);
        }
    } catch (e) {
        console.error('❌ Attack simulation error:', e);
    }
  };

  const triggerAnalysis = async () => {
    setAnalyzing(true);
    try {
        const res = await fetch('http://localhost:8000/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        if (res.ok) {
            const data = await res.json();
            if (data.analysis) {
                setAnalysis(data.analysis);
            }
        } else {
            alert('Failed to generate analysis');
        }
    } catch (e) {
        console.error(e);
        alert('Failed to generate analysis');
    } finally {
        setAnalyzing(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0f0f0f] text-gray-200 font-mono p-6">
      <header className="mb-8 bg-[#1a1a1a] border border-[#2a2a2a] rounded-lg p-6 lg:p-8">
        <div className="flex flex-col lg:flex-row lg:justify-between lg:items-center gap-6 lg:gap-8">
          <div className="flex-shrink-0">
            <h1 className="text-3xl lg:text-4xl font-bold text-white">
              ShieldOS
            </h1>
            <p className="text-sm text-gray-400 mt-1">Real-time Threat Detection System</p>
          </div>
          
          <div className="flex flex-col xl:flex-row gap-4 items-stretch xl:items-center flex-wrap w-full lg:flex-1 lg:min-w-0 lg:max-w-full overflow-hidden">
            <div className="flex flex-col sm:flex-row gap-3 flex-shrink-0">
              <input 
                type="text" 
                placeholder="Phone Number" 
                className="bg-[#1a1a1a] border border-[#2a2a2a] rounded px-4 py-2.5 text-sm focus:outline-none focus:border-gray-500 w-full sm:w-48 lg:w-64 text-gray-200"
                value={phoneNumber}
                onChange={(e) => setPhoneNumber(e.target.value)}
              />
              <input 
                type="number" 
                placeholder="Port (8000)" 
                className="bg-[#1a1a1a] border border-[#2a2a2a] rounded px-4 py-2.5 text-sm focus:outline-none focus:border-gray-500 w-full sm:w-32 lg:w-40 text-gray-200"
                value={monitoredPort}
                onChange={(e) => setMonitoredPort(e.target.value)}
              />
            </div>
            <button 
              onClick={handleSetConfig}
              className="bg-[#1a1a1a] border border-[#2a2a2a] rounded px-5 lg:px-6 py-2.5 text-sm text-white font-medium hover:bg-[#222] transition-colors whitespace-nowrap flex-shrink-0"
            >
              Save Config
            </button>
            <div className="flex gap-3 flex-wrap flex-shrink-0">
              <button 
                onClick={triggerAnalysis}
                disabled={analyzing}
                className="bg-[#1a1a1a] border border-[#2a2a2a] rounded px-5 lg:px-6 py-2.5 text-sm text-white font-medium hover:bg-[#222] transition-colors disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap"
                title="Generate Analysis Report"
              >
                {analyzing ? '⏳ Analyzing...' : '📊 Analyze'}
              </button>
              <button 
                onClick={() => simulateAttack('sqli')}
                className="bg-[#1a1a1a] border border-[#2a2a2a] rounded px-4 lg:px-5 py-2.5 text-sm text-yellow-400 hover:bg-[#222] transition-colors whitespace-nowrap"
                title="Simulate SQL Injection"
              >
                🧪 SQLi
              </button>
              <button 
                onClick={() => simulateAttack('ddos')}
                className="bg-[#1a1a1a] border border-[#2a2a2a] rounded px-4 lg:px-5 py-2.5 text-sm text-red-400 hover:bg-[#222] transition-colors whitespace-nowrap"
                title="Simulate DDoS"
              >
                🧪 DDoS
              </button>
            </div>
            <div className={`bg-[#1a1a1a] border rounded px-5 lg:px-6 py-2.5 font-medium text-sm flex-shrink-0 ${connected ? 'border-green-600 text-green-400' : 'border-red-600 text-red-400'}`}>
            <div className="flex items-center gap-3">
              <span className={`w-3 h-3 rounded-full ${connected ? 'bg-green-500' : 'bg-red-500'}`}></span>
              {connected ? 'ONLINE' : 'OFFLINE'}
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Analysis Summary Section */}
      {analysis && (
        <div className="mb-6 bg-[#1a1a1a] border border-[#2a2a2a] rounded-lg overflow-hidden">
          <div className="p-4 border-b border-[#2a2a2a] flex justify-between items-center">
            <h2 className="font-bold flex items-center gap-2 text-base text-white">
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"></path>
              </svg>
              Analysis Report
            </h2>
            <span className="text-xs text-gray-400 font-mono">
              {new Date(analysis.timestamp).toLocaleTimeString()}
            </span>
          </div>
          
          <div className="p-4 space-y-4">
            <div className="grid grid-cols-3 gap-3">
              <div className="bg-[#0f0f0f] border border-[#2a2a2a] rounded p-3">
                <div className="text-xs text-gray-400 mb-1">Packets</div>
                <div className="text-xl font-bold text-cyan-400">{analysis.overview.total_packets}</div>
              </div>
              <div className="bg-[#0f0f0f] border border-[#2a2a2a] rounded p-3">
                <div className="text-xs text-gray-400 mb-1">Alerts</div>
                <div className="text-xl font-bold text-red-400">{analysis.overview.total_alerts}</div>
              </div>
              <div className="bg-[#0f0f0f] border border-[#2a2a2a] rounded p-3">
                <div className="text-xs text-gray-400 mb-1">Pkts/sec</div>
                <div className="text-xl font-bold text-green-400">{analysis.overview.packets_per_second.toFixed(2)}</div>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="bg-[#0f0f0f] border border-[#2a2a2a] rounded p-3">
                <h3 className="font-bold text-white text-sm mb-2">Threats</h3>
                <div className="space-y-1.5 text-xs">
                  <div className="flex justify-between">
                    <span className="text-gray-400">DDoS:</span>
                    <span className="text-red-400 font-bold">{analysis.threats.ddos_count}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">SQLi:</span>
                    <span className="text-red-400 font-bold">{analysis.threats.sqli_count}</span>
                  </div>
                </div>
              </div>

              <div className="bg-[#0f0f0f] border border-[#2a2a2a] rounded p-3">
                <h3 className="font-bold text-white text-sm mb-2">Top Source</h3>
                <div className="text-xs">
                  {Object.keys(analysis.traffic.top_source_ips).length > 0 ? (
                    Object.entries(analysis.traffic.top_source_ips).slice(0, 1).map(([ip, count]) => (
                      <div key={ip} className="flex justify-between">
                        <span className="text-gray-500 font-mono">{ip}</span>
                        <span className="text-cyan-400">{count}</span>
                      </div>
                    ))
                  ) : (
                    <span className="text-gray-500">None</span>
                  )}
                </div>
              </div>
            </div>

            {/* LLM Analysis - Compact */}
            {analysis.llm_analysis && (
              <div className="bg-[#0f0f0f] border border-[#2a2a2a] rounded p-3">
                <h3 className="font-bold text-white text-sm mb-2 flex items-center gap-2">
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"></path>
                  </svg>
                  AI Analysis
                </h3>
                <div className="text-xs text-gray-300 leading-relaxed whitespace-pre-wrap">
                  {analysis.llm_analysis}
                </div>
              </div>
            )}

            {/* Mermaid Diagram - Client-side only to prevent hydration errors */}
            {analysis.mermaid_diagram && (
              <div className="bg-[#0f0f0f] border border-[#2a2a2a] rounded p-3">
                <h3 className="font-bold text-white text-sm mb-3 flex items-center gap-2">
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"></path>
                  </svg>
                  Attack Flow Diagram
                </h3>
                <div 
                  ref={mermaidRef} 
                  className="overflow-x-auto bg-[#1a1a1a] rounded p-4 min-h-[200px] flex items-center justify-center"
                  suppressHydrationWarning
                >
                  {!isClient && (
                    <div className="text-gray-500 text-xs">Loading diagram...</div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: HTTP Requests */}
        <div className="lg:col-span-2 space-y-6">
          <div className="bg-[#1a1a1a] border border-[#2a2a2a] rounded-lg overflow-hidden">
            <div className="p-5 border-b border-[#2a2a2a] flex justify-between items-center">
              <h2 className="font-bold flex items-center gap-3 text-lg text-white">
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
                Incoming HTTP Requests (Port 8000)
              </h2>
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></span>
                <span className="text-xs text-green-400 font-medium">Live</span>
                <span className="text-xs text-gray-400 font-mono ml-2">({httpRequests.length})</span>
              </div>
            </div>
            <div className="p-6 h-[500px] overflow-y-auto font-mono text-xs">
              {httpRequests.length === 0 ? (
                <div className="text-center text-gray-500 mt-20">
                  <p className="font-medium mb-2">No requests yet</p>
                  <p className="text-xs">Waiting for incoming traffic on port 8000...</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {httpRequests.map((req, i) => {
                    const isThreat = req.threat_type !== null && req.threat_type !== undefined;
                    const isSqlInjection = req.threat_type === 'SQL Injection';
                    const isBlocked = req.blocked === true;
                    
                    return (
                      <div
                        key={i}
                        className={`border rounded-lg p-4 transition-colors ${
                          isBlocked && isSqlInjection
                            ? 'bg-red-950/40 border-red-700/60 hover:bg-red-950/50 ring-2 ring-red-600/30'
                            : isBlocked
                            ? 'bg-yellow-950/30 border-yellow-700/60 hover:bg-yellow-950/40 ring-2 ring-yellow-600/30'
                            : isSqlInjection
                            ? 'bg-red-950/30 border-red-600/50 hover:bg-red-950/40'
                            : isThreat
                            ? 'bg-yellow-950/20 border-yellow-600/50 hover:bg-yellow-950/30'
                            : 'bg-[#0f0f0f] border-[#2a2a2a] hover:bg-[#151515]'
                        }`}
                      >
                        <div className="flex items-start justify-between mb-2">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className={`font-bold px-2 py-0.5 rounded text-xs ${
                              req.method === 'GET' ? 'bg-blue-900/50 text-blue-300' :
                              req.method === 'POST' ? 'bg-purple-900/50 text-purple-300' :
                              'bg-gray-800 text-gray-300'
                            }`}>
                              {req.method}
                            </span>
                            <span className="text-white font-medium">{req.path}</span>
                            {req.query && (
                              <span className="text-gray-400 text-xs">?{req.query.substring(0, 50)}{req.query.length > 50 ? '...' : ''}</span>
                            )}
                            {isBlocked && (
                              <span className={`px-2 py-0.5 rounded text-xs font-bold animate-pulse ${
                                isSqlInjection
                                  ? 'bg-red-700 text-white'
                                  : 'bg-yellow-700 text-white'
                              }`}>
                                🛡️ BLOCKED
                              </span>
                            )}
                            {isThreat && !isBlocked && (
                              <span className={`px-2 py-0.5 rounded text-xs font-bold ${
                                isSqlInjection
                                  ? 'bg-red-600 text-white'
                                  : 'bg-yellow-600 text-black'
                              }`}>
                                ⚠️ {req.threat_type}
                              </span>
                            )}
                            {isThreat && isBlocked && (
                              <span className={`px-2 py-0.5 rounded text-xs font-bold ${
                                isSqlInjection
                                  ? 'bg-red-600 text-white'
                                  : 'bg-yellow-600 text-black'
                              }`}>
                                {req.threat_type}
                              </span>
                            )}
                          </div>
                          <span className="text-gray-500 text-xs">
                            {new Date(req.timestamp).toLocaleTimeString()}
                          </span>
                        </div>
                        
                        <div className="grid grid-cols-2 gap-2 text-xs mt-2">
                          <div>
                            <span className="text-gray-500">IP:</span>
                            <span className="text-cyan-400 ml-1 font-mono">{req.client_ip}</span>
                          </div>
                          {isBlocked && (
                            <div className="col-span-2">
                              <span className="text-gray-500">Status:</span>
                              <span className="ml-1 text-red-400 font-bold">
                                🛡️ Blocked by {req.blocked_by || 'ShieldOS'} - Request never reached application
                              </span>
                            </div>
                          )}
                          {isThreat && req.threat_details && (
                            <div className="col-span-2">
                              <span className="text-gray-500">Threat:</span>
                              <span className={`ml-1 ${
                                isSqlInjection ? 'text-red-400 font-bold' : 'text-yellow-400'
                              }`}>
                                {req.threat_details}
                              </span>
                            </div>
                          )}
                        </div>
                        
                        {req.body && typeof req.body === 'object' && (
                          <div className="mt-2 pt-2 border-t border-[#2a2a2a]">
                            <div className="text-gray-500 text-xs mb-1">Body:</div>
                            <pre className="text-xs text-gray-300 bg-[#0a0a0a] p-2 rounded overflow-x-auto">
                              {JSON.stringify(req.body, null, 2)}
                            </pre>
                          </div>
                        )}
                        
                        {req.body && typeof req.body === 'string' && req.body.length > 0 && (
                          <div className="mt-2 pt-2 border-t border-[#2a2a2a]">
                            <div className="text-gray-500 text-xs mb-1">Body:</div>
                            <div className="text-xs text-gray-300 bg-[#0a0a0a] p-2 rounded">
                              {req.body.substring(0, 200)}{req.body.length > 200 ? '...' : ''}
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Right Column: Alerts */}
        <div className="space-y-6">
          <div className="bg-[#1a1a1a] border border-[#2a2a2a] rounded-lg overflow-hidden">
            <div className="p-5 border-b border-[#2a2a2a] flex justify-between items-center">
              <h2 className="font-bold text-white flex items-center gap-3 text-lg">
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
                Threat Alerts
              </h2>
              <div className="bg-[#222] border border-[#2a2a2a] rounded px-3 py-1">
                <span className="text-xs text-red-400 font-medium">{alerts.length} Detected</span>
              </div>
            </div>
            <div className="p-6 h-[500px] overflow-y-auto space-y-4">
              {alerts.length === 0 ? (
                <div className="bg-[#0f0f0f] border border-[#2a2a2a] rounded-lg p-8 text-center text-gray-500 mt-20">
                  <svg className="w-16 h-16 mx-auto mb-4 opacity-30" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                  </svg>
                  <p className="font-medium">No active threats detected</p>
                  <p className="text-sm mt-2">System secure</p>
                </div>
              ) : (
                alerts.map((alert, i) => (
                  <div 
                    key={i} 
                    className="bg-[#0f0f0f] border border-red-900/50 rounded-lg p-4 hover:bg-[#151515] transition-colors"
                  >
                    <div className="flex justify-between items-start mb-3">
                      <div className="flex items-center gap-2">
                        <span className="w-2 h-2 bg-red-500 rounded-full"></span>
                        <span className="font-bold text-red-400 text-sm">{alert.type.toUpperCase()}</span>
                      </div>
                      <span className="text-xs text-gray-500 font-mono">
                        {new Date(alert.timestamp).toLocaleTimeString()}
                      </span>
                    </div>
                    <div className="text-xs text-gray-300 mb-3 leading-relaxed">
                      {alert.message}
                    </div>
                    <div className="bg-[#1a1a1a] border border-[#2a2a2a] rounded text-xs font-mono p-2 text-gray-400">
                      <span className="text-gray-500">Source:</span> {alert.source}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
