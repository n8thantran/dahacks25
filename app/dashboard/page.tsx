'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';

export default function DashboardPage() {
  const [user, setUser] = useState<any>(null);

  useEffect(() => {
    // Simulate fetching user data
    const storedUser = localStorage.getItem('bankUser');
    if (storedUser) {
      setUser(JSON.parse(storedUser));
    }
  }, []);

  return (
    <div className="container">
      <div className="bank-header">
        <div className="bank-logo">Meridian Trust Bank</div>
        <div className="bank-tagline">Secure Banking Since 1847</div>
      </div>

      <div className="bank-content">
        <div className="dashboard">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '40px' }}>
            <h1 style={{ margin: 0 }}>Account Dashboard</h1>
            <Link href="/login" className="back-link">Sign Out</Link>
          </div>

          <div className="account-summary">
            <h2>Account Summary</h2>
            <div className="account-info">
              <div className="account-item">
                <label>Checking Account</label>
                <div className="value">$12,547.83</div>
              </div>
              <div className="account-item">
                <label>Savings Account</label>
                <div className="value">$45,230.12</div>
              </div>
              <div className="account-item">
                <label>Total Assets</label>
                <div className="value">$57,777.95</div>
              </div>
            </div>
          </div>

          <div className="section">
            <h2>Recent Transactions</h2>
            <p style={{ color: 'var(--bank-text-light)', fontStyle: 'italic' }}>
              Transaction history would appear here. This is a demo interface.
            </p>
          </div>

          <div className="section">
            <h2>Quick Actions</h2>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '20px', marginTop: '20px' }}>
              <button className="button-gold" style={{ padding: '20px' }}>
                Transfer Funds
              </button>
              <button style={{ padding: '20px' }}>
                Pay Bills
              </button>
              <button style={{ padding: '20px' }}>
                View Statements
              </button>
            </div>
          </div>

          <div className="warning" style={{ marginTop: '40px' }}>
            <strong>⚠️ This is a demonstration interface only</strong>
            This application contains security vulnerabilities for educational purposes. 
            No actual banking operations are performed.
          </div>
        </div>
      </div>
    </div>
  );
}

