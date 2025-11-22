'use client';

import { useState } from 'react';
import Link from 'next/link';

export default function CommentsPage() {
  const [postId, setPostId] = useState('1');
  const [userId, setUserId] = useState('1');
  const [comment, setComment] = useState('');
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setResult(null);

    try {
      const response = await fetch('/api/comments', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ post_id: postId, user_id: userId, comment }),
      });

      const data = await response.json();
      setResult(data);
    } catch (error: any) {
      setResult({ success: false, error: error.message });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container">
      <h1>SQL Injection - Comments</h1>
      <Link href="/">← Back to Home</Link>

      <div className="section">
        <h2>Vulnerable Comment Form</h2>
        <p><strong>Vulnerability:</strong> SQL injection in INSERT statements</p>
        
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Post ID:</label>
            <input
              type="text"
              value={postId}
              onChange={(e) => setPostId(e.target.value)}
              placeholder="1"
            />
          </div>
          
          <div className="form-group">
            <label>User ID:</label>
            <input
              type="text"
              value={userId}
              onChange={(e) => setUserId(e.target.value)}
              placeholder="1"
            />
          </div>
          
          <div className="form-group">
            <label>Comment:</label>
            <textarea
              value={comment}
              onChange={(e) => setComment(e.target.value)}
              rows={4}
              placeholder="test'); DROP TABLE posts; --"
            />
          </div>
          
          <button type="submit" disabled={loading}>
            {loading ? 'Submitting...' : 'Add Comment'}
          </button>
        </form>

        {result && (
          <div className={`result ${result.success ? '' : 'error'}`}>
            <pre>{JSON.stringify(result, null, 2)}</pre>
          </div>
        )}

        <div className="example-payloads">
          <strong>Try these payloads:</strong>
          <pre>{`Comment: test'); DROP TABLE posts; --
Comment: '), (1, 1, 'injected'); --
Comment: '); UPDATE users SET password='hacked'; --`}</pre>
        </div>
      </div>
    </div>
  );
}

