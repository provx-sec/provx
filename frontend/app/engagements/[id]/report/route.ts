// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Solomon Nii Amu Darku
import { isEngagementId, PROVX_API_BASE_URL } from "@/lib/api";

/** A fresh 404 per call - a Response body is a single-use stream and cannot be shared. */
function notFoundResponse(): Response {
  return new Response("Report unavailable.", {
    status: 404,
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
}

/**
 * Same-origin proxy for an engagement's HTML report.
 *
 * The report is opened by the browser, which cannot resolve the API's internal address, so
 * the request is relayed server-side. The upstream endpoint is unauthenticated in the
 * walking skeleton; when auth lands this handler is where the session check and rate limit
 * belong (rule S-08).
 */
export async function GET(
  _request: Request,
  { params }: { params: { id: string } },
): Promise<Response> {
  // Checked before any upstream call, so a malformed id never reaches the API.
  if (!isEngagementId(params.id)) {
    return notFoundResponse();
  }

  const upstream = await fetch(
    `${PROVX_API_BASE_URL}/engagements/${encodeURIComponent(params.id)}/report`,
    { cache: "no-store" },
  );

  if (!upstream.ok) {
    console.error(
      `Provx API returned ${upstream.status} rendering the report for ${params.id}`,
    );
    if (upstream.status === 404) {
      return notFoundResponse();
    }
    return new Response("Report unavailable.", {
      status: 502,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }

  return new Response(await upstream.text(), {
    status: 200,
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}
