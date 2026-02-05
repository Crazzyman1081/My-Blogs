import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import "./code-styles.css";
import Sidebar from "@/components/Sidebar";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "CTF Writeups",
  description: "Reverse Engineering & CTF Writeups",
  icons: {
    icon: `${process.env.NEXT_PUBLIC_BASE_PATH || ''}/pfp.jpg`,
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
              backgroundImage: `url('${process.env.NEXT_PUBLIC_BASE_PATH || ''}/vine.png')`
            }}
          ></div>
        </div>
      </body>
    </html>
  );
}
