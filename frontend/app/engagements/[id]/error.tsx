// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Solomon Nii Amu Darku
"use client";

/**
 * Route-segment error boundary (rule W-NEXT-03).
 *
 * Shows a fixed, user-safe message. The underlying error is logged server-side by the
 * fetch helper and is never rendered here (rules W-NEXT-09, S-13).
 */
export default function EngagementError({ reset }: { error: Error; reset: () => void }) {
  return (
    <main className="mx-auto flex min-h-screen max-w-2xl flex-col justify-center gap-4 px-6">
      <h1 className="text-xl font-semibold">Could not load findings</h1>
      <p className="text-sm text-neutral-500">
        The findings for this engagement are unavailable right now. Check that the
        engagement exists and that the Provx API is reachable.
      </p>
      <button
        type="button"
        onClick={reset}
        className="self-start rounded-md border border-neutral-400 px-3 py-1.5 text-sm hover:bg-neutral-100 dark:hover:bg-neutral-800"
      >
        Try again
      </button>
    </main>
  );
}
