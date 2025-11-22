'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';

export default function LoginPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const router = useRouter();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setResult(null);

    try {
      const response = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });

      const data = await response.json();
      setResult(data);
      
      // If login successful, save user and redirect to dashboard
      if (data.success) {
        if (typeof window !== 'undefined') {
          localStorage.setItem('bankUser', JSON.stringify(data.user));
        }
        setTimeout(() => {
          router.push('/dashboard');
        }, 1500);
      }
    } catch (error: any) {
      setResult({ success: false, error: error.message });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container">
      <div className="bank-header">
        <div className="bank-logo">Meridian Trust Bank</div>
        <div className="bank-tagline">Secure Banking Since 1847</div>
      </div>

      <div className="bank-content">
        <Link href="/" className="back-link">← Back to Home</Link>

        <div className="login-container">
          <div className="login-header">
            <h1>Online Banking</h1>
            <p>Sign in to access your accounts</p>
          </div>

          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label htmlFor="username">Username or Account Number</label>
              <input
                id="username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter your username"
                required
              />
            </div>
            
            <div className="form-group">
              <label htmlFor="password">Password</label>
              <input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter your password"
                required
              />
            </div>
            
            <button type="submit" disabled={loading} className="button-gold" style={{ width: '100%' }}>
              {loading ? 'Signing In...' : 'Sign In'}
            </button>
          </form>

          {result && (
            <div className={`result ${result.success ? 'success' : 'error'}`} style={{ marginTop: '25px' }}>
              {result.success ? (
                <div>
                  <h3 style={{ color: 'var(--bank-success)', marginTop: 0 }}>✓ Login Successful</h3>
                  <p>Welcome, {result.user?.username || 'User'}. Redirecting to your account dashboard...</p>
                </div>
              ) : (
                <div>
                  <h3 style={{ color: 'var(--bank-error)', marginTop: 0 }}>✗ Authentication Failed</h3>
                  <p>{result.message || result.error || 'Invalid credentials. Please try again.'}</p>
                </div>
              )}
            </div>
          )}

          <div style={{ marginTop: '30px', textAlign: 'center' }}>
            <Link href="#" style={{ color: 'var(--bank-teal)', textDecoration: 'none', fontSize: '0.9em' }}>
              Forgot Password?
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
