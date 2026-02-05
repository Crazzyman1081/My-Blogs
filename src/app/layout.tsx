import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import "./code-styles.css";
import Sidebar from "@/components/Sidebar";

const inter = Inter({ subsets: ["latin"] });
const basePath = process.env.NODE_ENV === 'production' ? '/My-Blogs' : '';

export const metadata: Metadata = {
  title: "CTF Writeups",
  description: "Reverse Engineering & CTF Writeups",
  icons: {
    icon: `${basePath}/pfp.jpg`,
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={inter.className}>
        <div className="layout-wrapper">
          <Sidebar />
          <main className="main-content">
            {children}
          </main>
          {/* Global Diagonal Vine */}
          <div
            className="vine-diagonal"
            style={{
              backgroundImage: `url('${basePath}/vine.png')`
            }}
          ></div>
        </div>
      </body>
    </html>
  );
}
