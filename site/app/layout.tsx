import { Inter } from 'next/font/google';
import { Provider } from '@/components/provider';
import './global.css';
import type { Metadata } from 'next';

import { siteDescription, siteName, siteUrl, withBase } from '@/lib/seo';

export const metadata: Metadata = {
  // absolute URLs for og:image / twitter:image -- without this Next falls back
  // to http://localhost:3000 and every shared link gets a broken preview
  metadataBase: new URL(siteUrl),
  title: { default: siteName, template: '%s | The Red-Book' },
  description: siteDescription,
  applicationName: siteName,
  alternates: { canonical: siteUrl },
  openGraph: {
    type: 'website',
    siteName,
    url: siteUrl,
    title: siteName,
    description: siteDescription,
  },
  twitter: { card: 'summary_large_image', title: siteName, description: siteDescription },
  robots: { index: true, follow: true },
  icons: {
    // the inner "8" is white in one mark and near-black in the other, so the
    // tab icon has to follow the browser theme or it disappears on one of them
    icon: [
      { url: withBase('/icon-light.png'), media: '(prefers-color-scheme: light)' },
      { url: withBase('/icon-dark.png'), media: '(prefers-color-scheme: dark)' },
    ],
    apple: withBase('/apple-icon.png'),
  },
};

const inter = Inter({
  subsets: ['latin'],
});

export default function Layout({ children }: LayoutProps<'/'>) {
  return (
    <html lang="en" className={inter.className} suppressHydrationWarning>
      <body className="flex flex-col min-h-screen">
        <Provider>{children}</Provider>
      </body>
    </html>
  );
}
