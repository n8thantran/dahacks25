'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';

export default function UsersPage() {
  const [orderBy, setOrderBy] = useState('id');
  const [limit, setLimit] = useState('10');
  const [results, setResults] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const fetchUsers = async () => {
    setLoading(true);
    try {
      const response = await fetch(`/api/users?order=${encodeURIComponent(orderBy)}&limit=${encodeURIComponent(limit)}`);
      const data = await response.json();
      setResults(data);
    } catch (error: any) {
      setResults({ error: error.message });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, [orderBy, limit]);

  return (
    <div className="container">
      <h1>SQL Injection - User List</h1>
      <Link href="/">← Back to Home</Link>

      <div className="section">
        <h2>Vulnerable User Listing</h2>
        <p><strong>Vulnerability:</strong> SQL injection in ORDER BY and LIMIT clauses</p>
        
        <div className="form-group">
          <label>Order By:</label>
          <input
            type="text"
            value={orderBy}
            onChange={(e) => setOrderBy(e.target.value)}
            placeholder="id; DROP TABLE users; --"
          />
        </div>
        
        <div className="form-group">
          <label>Limit:</label>
          <input
            type="text"
            value={limit}
            onChange={(e) => setLimit(e.target.value)}
            placeholder="10"
          />
        </div>
        
        <button onClick={fetchUsers} disabled={loading}>
          {loading ? 'Loading...' : 'Refresh'}
        </button>

        {results && (
          <div className="result">
            <pre>{JSON.stringify(results, null, 2)}</pre>
          </div>
        )}

        <div className="example-payloads">
          <strong>Try these payloads:</strong>
          <pre>{`Order: id; DROP TABLE users; --
Order: (SELECT password FROM users LIMIT 1)
Limit: 10; DELETE FROM users; --`}</pre>
        </div>
      </div>
    </div>
  );
}

