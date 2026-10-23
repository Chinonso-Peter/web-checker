import { useState, useEffect } from "react";
import { useNavigate, Link } from "react-router-dom";
import { startScan, getAuth, getScanHistory } from "../api/apiClient.js";

const MODULES = [
  {
    number: "01",
    purpose: "module-sqli",
    icon: (
      <svg className="w-3.5 h-3.5 text-zinc-300" fill="none" stroke="currentColor" strokeWidth="1.8" viewBox="0 0 24 24">
        <path d="M4 7c0-2.21 3.58-4 8-4s8 1.79 8 4m-16 5c0 2.21 3.58 4 8 4s8-1.79 8-4m-16 5c0 2.21 3.58 4 8 4s8-1.79 8-4M4 7v10c0 2.21 3.58 4 8 4s8-1.79 8-4V7" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    ),
    title: "SQL Injection",
    desc: "Injects test payloads into forms and parameters to detect unvalidated database queries.",
    category: "Data Layer"
  },
  {
    number: "02",
    purpose: "module-xss",
    icon: (
      <svg className="w-3.5 h-3.5 text-zinc-300" fill="none" stroke="currentColor" strokeWidth="1.8" viewBox="0 0 24 24">
        <path d="M16 18l6-6-6-6M8 6l-6 6 6 6" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    ),
    title: "Cross-Site Scripting (XSS)",
    desc: "Checks whether user input is reflected back and executed as a script in the browser.",
    category: "Client Script"
  },
  {
    number: "03",
    purpose: "module-bac",
    icon: (
      <svg className="w-3.5 h-3.5 text-zinc-300" fill="none" stroke="currentColor" strokeWidth="1.8" viewBox="0 0 24 24">
        <circle cx="12" cy="12" r="9" />
        <path d="M12 3v18M3 12h18" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    ),
    title: "Broken Access Control",
    desc: "Probes administrative pages, debug dumps and object endpoints (BOLA/IDOR) for missing authorization.",
    category: "Privilege Gate"
  },
  {
    number: "04",
    purpose: "module-crypto",
    icon: (
      <svg className="w-3.5 h-3.5 text-zinc-300" fill="none" stroke="currentColor" strokeWidth="1.8" viewBox="0 0 24 24">
        <path d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    ),
    title: "Cryptographic Failures",
    desc: "Verifies HTTPS enforcement, HSTS headers, and secure cookie transport flags.",
    category: "Transport / TLS"
  },
  {
    number: "05",
    purpose: "module-auth",
    icon: (
      <svg className="w-3.5 h-3.5 text-zinc-300" fill="none" stroke="currentColor" strokeWidth="1.8" viewBox="0 0 24 24">
        <path d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    ),
    title: "Authentication Failures",
    desc: "Reviews login forms for credential stuffing, missing rate limiting, and username enumeration.",
    category: "Session & Login"
  }
];

export default function DashboardPage() {
  const [url, setUrl] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [history, setHistory] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const navigate = useNavigate();
  const authed = Boolean(getAuth());

  useEffect(() => {
    if (authed) {
      setHistoryLoading(true);
      getScanHistory()
        .then((res) => {
          if (res && res.scans) {
            setHistory(res.scans);
          }
        })
        .catch(() => {})
        .finally(() => setHistoryLoading(false));
    }
  }, [authed]);

  const onSubmit = async (e) => {
    e.preventDefault();
    setError("");
    const trimmed = url.trim();
    if (!/^https?:\/\/.+/i.test(trimmed)) {
      setError("Enter a valid URL starting with http:// or https://");
      return;
    }
    setLoading(true);
    try {
      const res = await startScan(trimmed);
      navigate(`/report/${res.scanId}`);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col">
      {/* BEGIN: HeroSection */}
      <section className="border border-brand-border rounded-lg bg-brand-surface p-8 sm:p-10 md:p-12 mb-10 relative overflow-hidden" data-purpose="hero-module">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
          {/* Left Column: Copy & Actions */}
          <div className="lg:col-span-8 flex flex-col">
            <div className="inline-flex items-center gap-2 mb-4">
              <span className="w-1.5 h-1.5 rounded-full bg-white animate-pulse" />
              <span className="text-[11px] font-mono tracking-wider uppercase text-brand-muted">Vulnerability Scanner Engine</span>
            </div>
            <h1 className="text-2xl sm:text-3xl lg:text-4xl font-semibold tracking-tight text-white leading-tight mb-5 max-w-2xl">
              Automated security scan for your web app
            </h1>
            <p className="text-sm sm:text-base text-zinc-300 leading-relaxed max-w-2xl mb-4 font-normal">
              Point Web Checker at any URL you control and get a clear report on the five most common online vulnerabilities — SQL injection, XSS, broken access control, cryptographic failures and authentication issues.
            </p>
            <p className="text-xs sm:text-sm text-brand-muted mb-8 leading-normal max-w-xl">
              Scans are restricted to registered users. Sign in to start a scan and store your report history.
            </p>

            {/* Actions: Scan bar if logged in, auth buttons if logged out */}
            {authed ? (
              <div className="max-w-xl">
                <form className="flex flex-col sm:flex-row gap-2" onSubmit={onSubmit}>
                  <input
                    name="targetUrl"
                    className="flex-1 h-10 px-3.5 rounded bg-brand-black border border-brand-border text-white text-xs font-mono placeholder:text-zinc-500 focus:outline-none focus:border-zinc-400"
                    placeholder="https://example.com"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    aria-label="Target URL"
                  />
                  <button
                    type="submit"
                    className={`relative overflow-hidden inline-flex items-center justify-center px-6 h-10 text-xs font-mono font-medium rounded transition-all duration-300 ${
                      loading
                        ? "bg-zinc-950 border border-teal-500/60 text-teal-300 animate-scan-glow cursor-wait"
                        : "bg-white text-black border border-white hover:bg-zinc-200"
                    }`}
                    disabled={loading}
                  >
                    {loading && (
                      <>
                        <span className="absolute inset-0 w-full h-full bg-gradient-to-r from-transparent via-teal-400/35 to-transparent animate-scan-beam pointer-events-none" />
                        <span className="relative flex items-center justify-center w-4 h-4 mr-2.5">
                          <span className="absolute w-3.5 h-3.5 rounded-full border border-teal-400/40 animate-ping opacity-75" />
                          <svg className="w-3.5 h-3.5 text-teal-300 animate-radar-sweep" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <circle cx="12" cy="12" r="10" strokeDasharray="3 3" />
                            <line x1="12" y1="12" x2="19" y2="5" strokeLinecap="round" />
                            <circle cx="12" cy="12" r="2" fill="currentColor" />
                          </svg>
                        </span>
                      </>
                    )}
                    <span className="relative z-10 font-semibold tracking-wider">
                      {loading ? "SCANNING…" : "Start Scan"}
                    </span>
                  </button>
                </form>
                {error && (
                  <p className="text-xs text-red-400 mt-2 flex items-center gap-1" role="alert">
                    <span aria-hidden="true">⚠</span>
                    {error}
                  </p>
                )}
                <p className="text-[11px] font-mono text-zinc-500 mt-2">
                  Only scan domains you are authorised to test.
                </p>
              </div>
            ) : (
              <div className="flex flex-wrap items-center gap-3" data-purpose="hero-actions">
                <Link
                  to="/login"
                  className="inline-flex items-center justify-center px-5 py-2.5 text-xs font-medium text-black bg-white rounded border border-white hover:bg-zinc-200 transition-colors focus:ring-2 focus:ring-offset-2 focus:ring-offset-brand-black focus:ring-white"
                >
                  Sign in to scan
                </Link>
                <Link
                  to="/register"
                  className="inline-flex items-center justify-center px-5 py-2.5 text-xs font-medium text-zinc-200 bg-brand-subtle rounded border border-brand-border hover:bg-brand-surface hover:text-white hover:border-zinc-600 transition-colors"
                >
                  Create an account
                </Link>
              </div>
            )}
          </div>
          {/* Right Column: Subtle Structured Scan Capability Preview */}
          <div className="lg:col-span-4 border-t lg:border-t-0 lg:border-l border-brand-border pt-6 lg:pt-0 lg:pl-8 text-xs text-brand-muted space-y-3 font-mono">
            <div className="text-[11px] text-zinc-400 uppercase tracking-wider">Audit Specifications</div>
            <div className="flex items-center justify-between text-zinc-400 border-b border-brand-border/40 pb-2">
              <span>Standard:</span>
              <span className="text-white">OWASP Top 10</span>
            </div>
            <div className="flex items-center justify-between text-zinc-400 border-b border-brand-border/40 pb-2">
              <span>Execution:</span>
              <span className="text-white">Non-destructive</span>
            </div>
            <div className="flex items-center justify-between text-zinc-400 border-b border-brand-border/40 pb-2">
              <span>Report Export:</span>
              <span className="text-white">JSON / PDF</span>
            </div>
            <div className="flex items-center justify-between text-zinc-400">
              <span>Modules:</span>
              <span className="text-white">5 Active Vectors</span>
            </div>
          </div>
        </div>
      </section>
      {/* END: HeroSection */}

      {/* BEGIN: Saved Audit Reports Table (Available for Logged-in Users) */}
      {authed && (
        <section className="mb-14">
          <div className="flex items-center justify-between mb-4 pb-2 border-b border-brand-border">
            <div className="flex items-center gap-2">
              <svg className="w-4 h-4 text-zinc-400" fill="none" stroke="currentColor" strokeWidth="1.8" viewBox="0 0 24 24">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                <polyline points="14 2 14 8 20 8" />
                <line x1="16" y1="13" x2="8" y2="13" />
                <line x1="16" y1="17" x2="8" y2="17" />
              </svg>
              <h2 className="text-xs font-mono font-medium tracking-widest uppercase text-brand-muted">
                SAVED AUDIT REPORTS
              </h2>
            </div>
            <span className="text-[11px] font-mono text-zinc-500">
              {history.length} {history.length === 1 ? "report" : "reports"} recorded
            </span>
          </div>

          <div className="border border-brand-border rounded-lg bg-brand-surface overflow-hidden">
            {historyLoading ? (
              <div className="p-8 text-center text-xs font-mono text-zinc-500">
                Loading audit reports…
              </div>
            ) : history.length === 0 ? (
              <div className="p-8 text-center text-xs font-mono text-zinc-500">
                No past security audits found. Enter a target URL above to launch your first scan.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-brand-black/60 border-b border-brand-border text-zinc-400 font-mono text-[11px] uppercase tracking-wider">
                    <tr>
                      <th className="px-5 py-3">Target Endpoint</th>
                      <th className="px-4 py-3">Status</th>
                      <th className="px-4 py-3">Risk Level</th>
                      <th className="px-4 py-3">Findings</th>
                      <th className="px-4 py-3">Audit Date</th>
                      <th className="px-5 py-3 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-brand-border/60">
                    {history.map((s) => {
                      const sev = s.highestSeverity || "none";
                      let badge = "bg-zinc-800 text-zinc-400 border-zinc-700";
                      if (sev === "critical") badge = "bg-white text-black font-semibold";
                      else if (sev === "high") badge = "bg-zinc-900 text-zinc-200 border-zinc-700";
                      else if (sev === "medium") badge = "bg-zinc-900 text-zinc-400 border-zinc-800";
                      else if (sev === "low") badge = "bg-zinc-900 text-zinc-500 border-zinc-850";

                      return (
                        <tr key={s.scanId} className="hover:bg-brand-subtle/50 transition-colors">
                          <td className="px-5 py-3.5 font-mono text-white font-medium truncate max-w-xs sm:max-w-sm">
                            {s.targetUrl}
                          </td>
                          <td className="px-4 py-3.5">
                            <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono uppercase ${
                              s.status === "completed" ? "bg-teal-500/10 text-teal-400 border border-teal-500/30" : "bg-zinc-800 text-zinc-400"
                            }`}>
                              {s.status}
                            </span>
                          </td>
                          <td className="px-4 py-3.5">
                            <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono uppercase border ${badge}`}>
                              {sev}
                            </span>
                          </td>
                          <td className="px-4 py-3.5 font-mono text-zinc-300">
                            {s.findingsCount}
                          </td>
                          <td className="px-4 py-3.5 font-mono text-zinc-500 text-[11px]">
                            {s.createdAt || "Just now"}
                          </td>
                          <td className="px-5 py-3.5 text-right font-mono">
                            <Link
                              to={`/report/${s.scanId}`}
                              className="inline-flex items-center gap-1 text-xs text-white hover:underline underline-offset-4 font-medium"
                            >
                              <span>View Report</span>
                              <span>→</span>
                            </Link>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </section>
      )}

      {/* BEGIN: VulnerabilitiesSection */}
      <section className="mb-14" data-purpose="modules-section">
        {/* Section Header */}
        <div className="flex items-center justify-between mb-4 pb-2 border-b border-brand-border">
          <h2 className="text-xs font-mono font-medium tracking-widest uppercase text-brand-muted">
            WHAT WE CHECK
          </h2>
          <span className="text-[11px] font-mono text-zinc-500">5 Modules Included</span>
        </div>
        {/* Cohesive 5-Card Matrix (Responsive Grid) */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
          {MODULES.map((m) => (
            <div
              key={m.title}
              className="p-5 rounded-lg border border-brand-border bg-brand-surface hover:border-zinc-500 transition-colors flex flex-col justify-between"
              data-purpose={m.purpose}
            >
              <div>
                <div className="flex items-center justify-between mb-4">
                  <div className="w-7 h-7 rounded border border-brand-border bg-brand-subtle flex items-center justify-center text-zinc-300">
                    {m.icon}
                  </div>
                  <span className="font-mono text-[10px] text-zinc-500 font-semibold tracking-wider">{m.number}</span>
                </div>
                <h3 className="text-sm font-semibold text-white mb-2 tracking-tight">{m.title}</h3>
                <p className="text-xs text-brand-muted leading-relaxed">
                  {m.desc}
                </p>
              </div>
              <div className="mt-6 pt-3 border-t border-brand-border/60 text-[10px] font-mono text-zinc-500 uppercase">
                {m.category}
              </div>
            </div>
          ))}
        </div>
      </section>
      {/* END: VulnerabilitiesSection */}

      {/* BEGIN: SeverityScaleSection */}
      <section className="border border-brand-border rounded-lg bg-brand-surface p-6" data-purpose="severity-scale">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          {/* Scale Label */}
          <div>
            <span className="text-xs font-mono font-medium tracking-widest uppercase text-brand-muted">
              FINDINGS SEVERITY SCALE
            </span>
            <p className="text-[11px] text-zinc-500 mt-0.5">Classification baseline used across all audit modules</p>
          </div>
          {/* Monochrome High-Contrast Badges */}
          <div className="flex flex-wrap items-center gap-2.5 font-mono text-xs">
            {/* Critical Badge */}
            <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded bg-zinc-900 border border-zinc-700 text-white">
              <span className="w-2 h-2 rounded-full bg-white ring-2 ring-white/20" />
              <span className="font-medium text-xs">Critical</span>
            </div>
            {/* High Badge */}
            <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded bg-zinc-900 border border-zinc-800 text-zinc-300">
              <span className="w-2 h-2 rounded-full bg-zinc-400" />
              <span className="font-medium text-xs">High</span>
            </div>
            {/* Medium Badge */}
            <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded bg-zinc-900 border border-zinc-800 text-zinc-400">
              <span className="w-2 h-2 rounded-full bg-zinc-600" />
              <span className="font-medium text-xs">Medium</span>
            </div>
            {/* Low Badge */}
            <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded bg-zinc-900 border border-zinc-850 text-zinc-500">
              <span className="w-2 h-2 rounded-full bg-zinc-700" />
              <span className="font-medium text-xs">Low</span>
            </div>
          </div>
        </div>
      </section>
      {/* END: SeverityScaleSection */}
    </div>
  );
}
