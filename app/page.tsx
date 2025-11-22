'use client';

import Link from 'next/link';

export default function Home() {
  return (
    <div className="container">
      <div className="bank-header">
        <div className="bank-logo">Meridian Trust Bank</div>
        <div className="bank-tagline">Secure Banking Since 1847</div>
      </div>

      <div className="bank-content">
        <div className="login-container">
          <div className="login-header">
            <h1>Welcome Back</h1>
            <p>Sign in to access your accounts</p>
          </div>

          <Link href="/login" className="button-gold" style={{ display: 'block', textAlign: 'center', textDecoration: 'none', padding: '16px 40px' }}>
            Sign In to Online Banking
          </Link>

          <div style={{ marginTop: '40px', textAlign: 'center', padding: '30px', background: '#f8f6f2', border: '1px solid var(--bank-border)' }}>
            <h3 style={{ marginTop: 0, marginBottom: '15px' }}>New to Meridian Trust?</h3>
            <p style={{ marginBottom: '20px', color: 'var(--bank-text-light)' }}>
              Experience secure, modern banking with our online platform.
            </p>
            <Link href="/login" style={{ color: 'var(--bank-teal)', textDecoration: 'none', fontWeight: 600 }}>
              Enroll Now →
            </Link>
          </div>
        </div>

        <div className="section" style={{ marginTop: '60px', background: 'transparent', border: 'none', boxShadow: 'none' }}>
          <p style={{ textAlign: 'center', fontSize: '0.9em', color: 'var(--bank-text-light)' }}>
            Meridian Trust Bank • Member FDIC • Equal Housing Lender
          </p>
        </div>
      </div>
    </div>
  );
}
