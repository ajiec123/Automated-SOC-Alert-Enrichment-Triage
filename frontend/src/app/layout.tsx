import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'Automated SOC Alert Enrichment & Triage Platform',
  description: 'Enterprise SIEM/SOAR Ingestion, Threat Intel Enrichment & Browser-Native PGlite PostgreSQL WASM Engine',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="bg-zinc-950 text-zinc-100 min-h-screen antialiased selection:bg-blue-600 selection:text-white">
        {children}
      </body>
    </html>
  );
}
