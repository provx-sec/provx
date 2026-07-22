// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Solomon Nii Amu Darku
import Link from "next/link";
import { notFound } from "next/navigation";

import { EngagementNotFoundError, getFindings, reportUrl } from "@/lib/api";

export const dynamic = "force-dynamic";

/**
 * An engagement's findings, fetched server-side from the Provx API.
 *
 * Rendering happens on the server, so the API base URL never reaches the browser and no
 * CORS surface is opened for the walking skeleton.
 */
export default async function EngagementFindingsPage({
  params,
}: {
  params: { id: string };
}) {
  // A malformed or unknown id is a 404, not an error screen: the error boundary is
  // reserved for real failures like the API being unreachable.
  let findings;
  try {
    findings = await getFindings(params.id);
  } catch (error) {
    if (error instanceof EngagementNotFoundError) {
      notFound();
    }
    throw error;
  }

  return (
    <main className="mx-auto flex min-h-screen max-w-5xl flex-col gap-6 px-6 py-10">
      <div className="flex flex-col gap-1">
        <Link href="/" className="text-sm text-neutral-500 hover:underline">
          &larr; Provx
        </Link>
        <h1 className="text-2xl font-semibold">Findings</h1>
        <p className="text-sm text-neutral-500">Engagement {params.id}</p>
      </div>

      {/* PX-HUMAN: the console must never present a machine finding as confirmed. */}
      <p className="rounded-md border border-amber-600 bg-amber-50 p-3 text-sm text-amber-900 dark:bg-amber-950 dark:text-amber-200">
        <strong>Machine-found, unvalidated.</strong> These findings were produced by a
        deterministic passive check and have not been confirmed by a human.
      </p>

      <p>
        <a
          href={reportUrl(params.id)}
          className="text-sm underline"
          rel="noreferrer"
        >
          Open the HTML report
        </a>
      </p>

      {findings.length === 0 ? (
        <p className="rounded-md border border-dashed border-neutral-300 p-8 text-center text-sm text-neutral-500">
          No findings recorded yet. Run a scan for this engagement.
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="border-b border-neutral-300 text-left">
                <th className="p-2">ID</th>
                <th className="p-2">Title</th>
                <th className="p-2">Target</th>
                <th className="p-2">Status</th>
                <th className="p-2">Severity</th>
                <th className="p-2">CVSS</th>
                <th className="p-2">ATT&amp;CK</th>
                <th className="p-2">Evidence</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((finding) => (
                <tr key={finding.id} className="border-b border-neutral-200">
                  <td className="p-2 font-mono text-xs">{finding.display_id}</td>
                  <td className="p-2">{finding.title}</td>
                  <td className="p-2 break-all">{finding.target}</td>
                  {/* Status makes the machine-vs-validated distinction visible in the console
                      too, not only in the report (rule PX-HUMAN). */}
                  <td className="p-2">{finding.status}</td>
                  <td className="p-2">{finding.severity}</td>
                  <td className="p-2">{finding.cvss ?? "-"}</td>
                  <td className="p-2">{finding.attack_techniques.join(", ") || "-"}</td>
                  <td className="p-2">{finding.evidence_ref_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </main>
  );
}
