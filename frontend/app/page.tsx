// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Solomon Nii Amu Darku
export default function Home() {
  return (
    <main className="mx-auto flex min-h-screen max-w-2xl flex-col justify-center gap-4 px-6">
      <h1 className="text-3xl font-semibold">Provx</h1>
      <p className="text-neutral-600 dark:text-neutral-400">
        Governed automated security validation — web, API &amp; infra in one console.
        Safe by default.
      </p>
      <p className="text-sm text-neutral-500">
        Phase 1 skeleton. The console is under construction — see the roadmap in{" "}
        <code>docs/ROADMAP.md</code>.
      </p>
    </main>
  );
}
