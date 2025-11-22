'use client';

import { useState } from 'react';
import Link from 'next/link';

export default function DDoSPage() {
  const [results, setResults] = useState<Record<string, any>>({});
  const [loading, setLoading] = useState<Record<string, boolean>>({});

  const runHeavyCompute = async () => {
    setLoading(prev => ({ ...prev, compute: true }));
    try {
      const response = await fetch('/api/ddos/heavy-compute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ iterations: 1000000, depth: 40 }),
      });
      const data = await response.json();
      setResults(prev => ({ ...prev, compute: data }));
    } catch (error: any) {
      setResults(prev => ({ ...prev, compute: { error: error.message } }));
    } finally {
      setLoading(prev => ({ ...prev, compute: false }));
    }
  };

  const runMemorySpike = async () => {
    setLoading(prev => ({ ...prev, memory: true }));
    try {
      const response = await fetch('/api/ddos/memory-spike', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ size: 1000 }),
      });
      const data = await response.json();
      setResults(prev => ({ ...prev, memory: data }));
    } catch (error: any) {
      setResults(prev => ({ ...prev, memory: { error: error.message } }));
    } finally {
      setLoading(prev => ({ ...prev, memory: false }));
    }
  };

  const runRecursiveFetch = async () => {
    setLoading(prev => ({ ...prev, recursive: true }));
    try {
      const response = await fetch('/api/ddos/recursive-fetch?depth=5&target=self');
      const data = await response.json();
      setResults(prev => ({ ...prev, recursive: data }));
    } catch (error: any) {
      setResults(prev => ({ ...prev, recursive: { error: error.message } }));
    } finally {
      setLoading(prev => ({ ...prev, recursive: false }));
    }
  };

  const runExpensiveQuery = async () => {
    setLoading(prev => ({ ...prev, query: true }));
    try {
      const response = await fetch('/api/ddos/expensive-query?joins=10');
      const data = await response.json();
      setResults(prev => ({ ...prev, query: data }));
    } catch (error: any) {
      setResults(prev => ({ ...prev, query: { error: error.message } }));
    } finally {
      setLoading(prev => ({ ...prev, query: false }));
    }
  };

  return (
    <div className="container">
      <h1>DDoS Vulnerabilities</h1>
      <Link href="/">← Back to Home</Link>

      <div className="section">
        <h2>CPU Exhaustion - Heavy Compute</h2>
        <p><strong>Vulnerability:</strong> No rate limiting, CPU-intensive recursive operations</p>
        <button onClick={runHeavyCompute} disabled={loading.compute}>
          {loading.compute ? 'Computing...' : 'Run Heavy Compute'}
        </button>
        {results.compute && (
          <div className="result">
            <pre>{JSON.stringify(results.compute, null, 2)}</pre>
          </div>
        )}
        <div className="attack-info">
          <strong>Attack:</strong> Send POST with {`{ iterations: 999999999, depth: 100 }`}
        </div>
      </div>

      <div className="section">
        <h2>Memory Exhaustion - Memory Spike</h2>
        <p><strong>Vulnerability:</strong> No memory limits, can exhaust server memory</p>
        <button onClick={runMemorySpike} disabled={loading.memory}>
          {loading.memory ? 'Allocating...' : 'Run Memory Spike'}
        </button>
        {results.memory && (
          <div className="result">
            <pre>{JSON.stringify(results.memory, null, 2)}</pre>
          </div>
        )}
        <div style={{ marginTop: '10px', padding: '10px', background: '#fff3cd', borderRadius: '6px', fontSize: '14px' }}>
          <strong>Attack:</strong> Send POST with {`{ size: 999999999 }`}
        </div>
      </div>

      <div className="section">
        <h2>Amplification - Recursive Fetch</h2>
        <p><strong>Vulnerability:</strong> Recursive API calls causing amplification attacks</p>
        <button onClick={runRecursiveFetch} disabled={loading.recursive}>
          {loading.recursive ? 'Fetching...' : 'Run Recursive Fetch'}
        </button>
        {results.recursive && (
          <div className="result">
            <pre>{JSON.stringify(results.recursive, null, 2)}</pre>
          </div>
        )}
        <div style={{ marginTop: '10px', padding: '10px', background: '#fff3cd', borderRadius: '6px', fontSize: '14px' }}>
          <strong>Attack:</strong> GET /api/ddos/recursive-fetch?depth=100&target=self
        </div>
      </div>

      <div className="section">
        <h2>Database Exhaustion - Expensive Query</h2>
        <p><strong>Vulnerability:</strong> Cartesian products creating massive JOIN operations</p>
        <button onClick={runExpensiveQuery} disabled={loading.query}>
          {loading.query ? 'Querying...' : 'Run Expensive Query'}
        </button>
        {results.query && (
          <div className="result">
            <pre>{JSON.stringify(results.query, null, 2)}</pre>
          </div>
        )}
        <div style={{ marginTop: '10px', padding: '10px', background: '#fff3cd', borderRadius: '6px', fontSize: '14px' }}>
          <strong>Attack:</strong> GET /api/ddos/expensive-query?joins=100
        </div>
      </div>
    </div>
  );
}

