import { useState } from "react";

const REMEDIES = {
  "SQL Injection":
    "Use parameterised queries / prepared statements with ORM or database drivers. Never concatenate user input directly into SQL statements. Apply least-privilege database user permissions and validate types strictly on the server.",
  "Cross-Site Scripting":
    "Encode user-controlled output contextually, implement a strict Content-Security-Policy (CSP), and utilize modern UI libraries that auto-escape strings by default.",
  "Broken Access Control":
    "Enforce authorisation checks on the server for every endpoint and request. Implement a default-deny policy, never rely on client-side state alone, and audit direct object references (IDOR).",
  "Cryptographic Failures":
    "Enforce HTTPS across all pages with HTTP Strict Transport Security (HSTS). Mark sensitive cookies with Secure, HttpOnly, and SameSite attributes, and employ robust algorithms like AES-256 and Argon2/bcrypt.",
  "Authentication Failures":
    "Implement cryptographic password hashing (Argon2 or bcrypt), rate-limiting and temporary account lockouts, session regeneration after authentication, and multi-factor authentication.",
};

export default function RemediationPanel({ category }) {
  const [open, setOpen] = useState(false);
  const remedy =
    REMEDIES[category] ||
    "Follow standard OWASP guidance for this vulnerability class and conduct automated regression tests after deploying code fixes.";

  return (
    <div className="mt-2">
      <button
        className="text-xs text-brand-muted hover:text-white underline underline-offset-2 transition-colors font-mono"
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
      >
        {open ? "Hide remediation guidelines" : "View remediation guidelines"}
      </button>

      {open && (
        <div className="mt-2.5 p-3.5 rounded bg-brand-black border border-brand-border text-xs text-zinc-300 leading-relaxed font-mono">
          <span className="block text-[10px] text-zinc-500 uppercase tracking-wider mb-1">Recommended Fix</span>
          <p className="m-0">{remedy}</p>
        </div>
      )}
    </div>
  );
}
