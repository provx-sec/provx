// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Solomon Nii Amu Darku

/**
 * Provx API client - placeholder.
 *
 * The real client is generated from the backend OpenAPI schema once it stabilizes.
 * For now this exports the default API base URL so the frontend can wire against it.
 */
export const PROVX_API_BASE_URL =
  process.env.PROVX_API_BASE_URL ?? "http://localhost:8000";
