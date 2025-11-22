'use client';

import { useState } from 'react';
import Link from 'next/link';

export default function SearchPage() {
  const [searchTerm, setSearchTerm] = useState('');
  const [results, setResults] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setResults(null);

    try {
      const response = await fetch(`/api/search?q=${encodeURIComponent(searchTerm)}`);
      const data = await response.json();
      setResults(data);
    } catch (error: any) {
      setResults({ error: error.message });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container">
      <h1>SQL Injection - Search</h1>
      <Link href="/">← Back to Home</Link>

      <div className="section">
        <h2>Vulnerable Search</h2>
        <p><strong>Vulnerability:</strong> SQL injection in LIKE clauses, can use UNION SELECT to extract data</p>
        
        <form onSubmit={handleSearch}>
          <div className="form-group">
            <label>Search Term:</label>
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="test' UNION SELECT username, password FROM users --"
            />
          </div>
          
          <button type="submit" disabled={loading}>
            {loading ? 'Searching...' : 'Search'}
          </button>
        </form>

        {results && (
          <div className="result">
            <pre>{JSON.stringify(results, null, 2)}</pre>
          </div>
        )}

        <div className="example-payloads">
          <strong>Try these payloads:</strong>
          <pre>{`test' UNION SELECT username, password FROM users --
' UNION SELECT 1, 2, 3, 4 FROM users --
test' AND 1=1 --`}</pre>
        </div>
      </div>
    </div>
  );
}

