import type { Metadata } from 'next';
import { JetBrains_Mono, Inter } from 'next/font/google';
import './globals.css';
import Link from 'next/link';
import { Shield } from 'lucide-react';

const inter = Inter({
  subsets: ['latin'],
  variable: '--font-sans',
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ['latin'],
  variable: '--font-mono',
});

export const metadata: Metadata = {
  title: 'Autonomous SOC Platform',
  description: 'AI-powered Security Operations Center',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body
        className={`${inter.variable} ${jetbrainsMono.variable} font-sans antialiased bg-background text-foreground min-h-screen`}
      >
        <nav className="sticky top-0 z-40 border-b border-border bg-card/80 backdrop-blur-md">
          <div className="flex h-14 items-center px-4 gap-6">
            <Link href="/" className="flex items-center gap-2 group">
              <Shield className="h-5 w-5 text-cyan-400 group-hover:text-cyan-300 transition-colors" />
              <span className="font-mono font-semibold text-sm text-foreground tracking-wide">
                Autonomous SOC Platform
              </span>
            </Link>

            <div className="flex items-center gap-1 ml-2">
              <NavLink href="/">Dashboard</NavLink>
              <NavLink href="/incidents">Incidents</NavLink>
            </div>

            <div className="ml-auto flex items-center gap-2">
              <div className="h-2 w-2 rounded-full bg-cyan-400 animate-pulse" />
              <span className="text-xs font-mono text-muted-foreground">LIVE</span>
            </div>
          </div>
        </nav>

        <main className="flex-1">{children}</main>
      </body>
    </html>
  );
}

function NavLink({
  href,
  children,
}: {
  href: string;
  children: React.ReactNode;
}) {
  return (
    <Link
      href={href}
      className="px-3 py-1.5 rounded-md text-sm font-medium text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
    >
      {children}
    </Link>
  );
}
