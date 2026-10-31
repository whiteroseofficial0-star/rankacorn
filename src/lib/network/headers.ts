export interface HeaderCheck {
  name: string;
  present: boolean;
  value?: string;
  weight: number;
  why: string;
  fix: string;
}

export interface HeaderGrade {
  score: number;
  max: number;
  grade: string;
  checks: HeaderCheck[];
}

const headerValue = (h: Record<string, string | string[] | undefined>, name: string): string | undefined => {
  const v = h[name.toLowerCase()];
  return Array.isArray(v) ? v.join(", ") : v;
};

/** Weighted, transparent security-header score (0-100). */
export function gradeSecurityHeaders(headers: Record<string, string | string[] | undefined>): HeaderGrade {
  const get = (n: string) => headerValue(headers, n);
  const csp = get("content-security-policy");
  const xfo = get("x-frame-options");
  const frameAncestors = !!csp && /frame-ancestors/i.test(csp);

  const checks: HeaderCheck[] = [
    {
      name: "Strict-Transport-Security", present: !!get("strict-transport-security"), value: get("strict-transport-security"), weight: 20,
      why: "Forces browsers to use HTTPS for future visits, preventing downgrade attacks.",
      fix: "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    {
      name: "Content-Security-Policy", present: !!csp, value: csp, weight: 25,
      why: "Limits which scripts and resources can run, reducing the impact of injected content.",
      fix: "Start with a report-only policy, then tighten it.",
    },
    {
      name: "X-Frame-Options", present: !!xfo || frameAncestors, value: xfo ?? (frameAncestors ? "covered by CSP frame-ancestors" : undefined), weight: 15,
      why: "Stops other sites embedding your pages and tricking users with clickjacking.",
      fix: "Add: X-Frame-Options: DENY (or CSP frame-ancestors 'none').",
    },
    {
      name: "X-Content-Type-Options", present: get("x-content-type-options")?.toLowerCase().includes("nosniff") ?? false,
      value: get("x-content-type-options"), weight: 10,
      why: "Stops browsers guessing content types and executing a file as another type.",
      fix: "Add: X-Content-Type-Options: nosniff",
    },
    {
      name: "Referrer-Policy", present: !!get("referrer-policy"), value: get("referrer-policy"), weight: 10,
      why: "Controls how much URL information leaks to other sites.",
      fix: "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    {
      name: "Permissions-Policy", present: !!get("permissions-policy"), value: get("permissions-policy"), weight: 10,
      why: "Switches off browser features (camera, geolocation, etc.) you do not use.",
      fix: "Add: Permissions-Policy: geolocation=(), camera=(), microphone=()",
    },
    {
      name: "Cross-Origin-Opener-Policy", present: !!get("cross-origin-opener-policy"), value: get("cross-origin-opener-policy"), weight: 5,
      why: "Isolates your browsing context from the pages that opened it.",
      fix: "Add: Cross-Origin-Opener-Policy: same-origin",
    },
    {
      name: "Cross-Origin-Resource-Policy", present: !!get("cross-origin-resource-policy"), value: get("cross-origin-resource-policy"), weight: 5,
      why: "Restricts which sites may embed your resources.",
      fix: "Add: Cross-Origin-Resource-Policy: same-origin",
    },
  ];

  const score = checks.reduce((n, c) => n + (c.present ? c.weight : 0), 0);
  const max = checks.reduce((n, c) => n + c.weight, 0);
  const grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 60 ? "D" : "F";
  return { score, max, grade, checks };
}
