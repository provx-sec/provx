// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Solomon Nii Amu Darku

/**
 * Server-side access to the Provx API.
 *
 * The base URL is deliberately not `NEXT_PUBLIC_`: every call here runs in a Server
 * Component, so the API stays unreachable from the browser and no backend address is
 * shipped in the client bundle.
 */

export const PROVX_API_BASE_URL =
  process.env.PROVX_API_BASE_URL ?? "http://localhost:8000";

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Whether a value is a well-formed RFC 4122 UUID.
 *
 * Engagement ids reach this app straight from the URL, so their shape is checked before
 * they are used to address the API (rule S-05).
 */
export function isEngagementId(value: string): boolean {
  return UUID_PATTERN.test(value);
}

export type Finding = {
  id: string;
  display_id: string;
  title: string;
  target: string;
  module: string;
  severity: string;
  cvss: number | null;
  confidence: string;
  status: string;
  in_report: boolean;
  evidence_ref_count: number;
  attack_techniques: string[];
  remediation: string | null;
  evidence_sha256: string;
  captured_at: string;
};

/** Raised when an engagement does not exist, or its id is not a well-formed UUID. */
export class EngagementNotFoundError extends Error {}

/**
 * Fetch an engagement's findings.
 *
 * Throws EngagementNotFoundError for a malformed or unknown id, and a generic Error for
 * anything else - the upstream body is never surfaced to the user, since it can carry
 * detail meant for operators (rules W-NEXT-09, S-13).
 */
export async function getFindings(engagementId: string): Promise<Finding[]> {
  if (!isEngagementId(engagementId)) {
    throw new EngagementNotFoundError("Malformed engagement id.");
  }

  const response = await fetch(
    `${PROVX_API_BASE_URL}/engagements/${encodeURIComponent(engagementId)}/findings`,
    { cache: "no-store" },
  );

  if (response.status === 404) {
    throw new EngagementNotFoundError("Engagement not found.");
  }

  if (!response.ok) {
    console.error(
      `Provx API returned ${response.status} for engagement ${engagementId}`,
    );
    throw new Error("Could not load findings for this engagement.");
  }

  return (await response.json()) as Finding[];
}

/**
 * Link to an engagement's HTML report.
 *
 * Same-origin on purpose: the browser cannot resolve the API's internal address, so the
 * report is served through this app's proxy route.
 */
export function reportUrl(engagementId: string): string {
  return `/engagements/${encodeURIComponent(engagementId)}/report`;
}
