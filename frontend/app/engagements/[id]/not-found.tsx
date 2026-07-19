// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Solomon Nii Amu Darku
import Link from "next/link";

/**
 * Shown when an engagement id is unknown or malformed.
 *
 * Deliberately says the same thing in both cases, so the page never reveals what shape a
 * valid id has (rules PX-ERRORS, S-13).
 */
export default function EngagementNotFound() {
  return (
    <main className="mx-auto flex min-h-screen max-w-2xl flex-col justify-center gap-4 px-6">
      <h1 className="text-xl font-semibold">Engagement not found</h1>
      <p className="text-sm text-neutral-500">
        No engagement matches that address. Check the link and try again.
      </p>
      <Link href="/" className="self-start text-sm underline">
        Back to Provx
      </Link>
    </main>
  );
}
