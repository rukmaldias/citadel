import React from 'react';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Layout from '@theme/Layout';
import Heading from '@theme/Heading';

const FEATURES = [
  {
    icon: '🔐',
    title: 'Three-Asset Chain of Trust',
    desc: 'codesign.bin → licence.bin → firmware.bin. Each asset is verified before the next is decrypted. Breaking the chain at any point halts execution immediately.',
  },
  {
    icon: '🧮',
    title: 'AES-256-GCM Encryption',
    desc: 'All assets are encrypted with authenticated AES-256-GCM. The authentication tag detects any tampering before a single byte of plaintext is produced.',
  },
  {
    icon: '🖊️',
    title: 'Ed25519 Code Signing',
    desc: 'An Ed25519 signature over all asset hashes is verified at startup. Certificate substitution and file tampering are caught in under 0.1 ms.',
  },
  {
    icon: '⚙️',
    title: 'Argon2id Key Derivation',
    desc: 'Licence and firmware keys are derived via Argon2id (64 MB, 3 iterations). GPU and brute-force attacks cost seconds per attempt — not nanoseconds.',
  },
  {
    icon: '🛡️',
    title: 'Anti-Analysis Defences',
    desc: 'Debugger, root, and emulator detection run at startup and every 10 000 VM instructions. Detected intrusions immediately zeroize all secrets.',
  },
  {
    icon: '⚡',
    title: 'LLVM Obfuscation (CFF + SUB)',
    desc: 'Control Flow Flattening and Instruction Substitution via a custom LLVM pass harden the release binary against static analysis.',
  },
  {
    icon: '🦀',
    title: 'Rust Native Core',
    desc: 'Memory safety by construction. No buffer overflows, no use-after-free. All secret bytes implement zeroize and are wiped on drop.',
  },
  {
    icon: '📦',
    title: 'Android Keystore Integration',
    desc: 'Customer-data keys are stored in hardware-backed Android Keystore (StrongBox or TEE). Keys never enter application memory.',
  },
  {
    icon: '🔍',
    title: 'SHA-256 Self-Integrity',
    desc: 'The .so binary hashes its own ELF .text segment at startup. Any binary patch that is not reflected in the embedded hash slot fails immediately.',
  },
];

function HeroBanner() {
  const {siteConfig} = useDocusaurusContext();
  return (
    <div className="hero-banner">
      <div className="hero-eyebrow">v0.1.0 · GPL-3.0 License</div>
      <Heading as="h1" className="hero-title">
        {siteConfig.title}
        <span className="hero-title-accent">Secure Android VM</span>
      </Heading>
      <p className="hero-tagline">{siteConfig.tagline}</p>
      <div className="hero-buttons">
        <Link className="btn-primary" to="/docs/intro">
          Read the Docs →
        </Link>
        <Link
          className="btn-secondary"
          href="https://github.com/rukmaldias/citadel">
          GitHub ↗
        </Link>
      </div>
    </div>
  );
}

function StatsBar() {
  return (
    <div className="stats-bar">
      <div className="stats-bar__inner">
        {[
          {value: '3', label: 'asset chain'},
          {value: 'AES-256', label: 'encryption'},
          {value: 'Argon2id', label: 'key derivation'},
          {value: '<0.1 ms', label: 'signature verify'},
          {value: 'API 24+', label: 'Android support'},
        ].map(({value, label}) => (
          <div className="stat" key={label}>
            <span className="stat__value">{value}</span>
            <span className="stat__label">{label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function FeaturesSection() {
  return (
    <section className="features-section">
      <Heading as="h2" className="section-title">
        Defence in Depth
      </Heading>
      <p className="section-subtitle">
        Nine independent security layers — each catching a different class of attack.
      </p>
      <div className="features-grid">
        {FEATURES.map(({icon, title, desc}) => (
          <div className="feature-card" key={title}>
            <span className="feature-card__icon">{icon}</span>
            <div className="feature-card__title">{title}</div>
            <p className="feature-card__desc">{desc}</p>
          </div>
        ))}
      </div>
    </section>
  );
}

function CtaStrip() {
  return (
    <div className="cta-strip">
      <Heading as="h2">Ready to harden your app?</Heading>
      <p>
        Follow the step-by-step guide to generate your signing keys, write firmware,
        and integrate the VM into your Android project.
      </p>
      <div className="hero-buttons">
        <Link className="btn-primary" to="/docs/asset-generation">
          Asset Generation Guide →
        </Link>
        <Link className="btn-secondary" to="/docs/architecture">
          Architecture Overview
        </Link>
      </div>
    </div>
  );
}

export default function Home(): JSX.Element {
  const {siteConfig} = useDocusaurusContext();
  return (
    <Layout title={siteConfig.title} description={siteConfig.tagline}>
      <main>
        <HeroBanner />
        <StatsBar />
        <FeaturesSection />
        <CtaStrip />
      </main>
    </Layout>
  );
}
