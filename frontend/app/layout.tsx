// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Solomon Nii Amu Darku
import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Provx",
  description: "Governed automated security validation — web, API & infra. Safe by default.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
