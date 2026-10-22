import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { getReport, downloadReportPdf } from "../api/apiClient.js";
import VulnerabilityTable from "../components/VulnerabilityTable.jsx";
import RemediationPanel from "../components/RemediationPanel.jsx";

const SEVERITIES = [
  { key: "critical", label: "Critical", border: "border-zinc-700", dot: "bg-white", text: "text-white" },
  { key: "high", label: "High", border: "border-zinc-800", dot: "bg-zinc-400", text: "text-zinc-300" },
  { key: "medium", label: "Medium", border: "border-zinc-800", dot: "bg-zinc-600", text: "text-zinc-400" },
  { key: "low", label: "Low", border: "border-zinc-850", dot: "bg-zinc-700", text: "text-zinc-500" },
];

const VERDICT_TEXT = {
  critical: "Critical risk — high-severity vulnerabilities detected that require immediate remediation before production deployment.",
  high: "High risk — serious security weaknesses found that should be addressed as a priority.",
  medium: "Medium risk — potential weaknesses detected, especially when chained with other vectors.",
  low: "Low risk — minor hardening opportunities and defense-in-depth improvements.",
  ok: "Clean report — no vulnerabilities were detected for the executed modules. The target appears hardened.",
};

function RiskVerdict({ highest }) {
  const isOk = highest === "ok";
  const label = isOk ? "Clean Audit Passed" : `${highest.toUpperCase()} RISK LEVEL`;

  return (
    <div className="p-6 rounded-lg border border-brand-border bg-brand-surface mb-8">
      <div className="flex items-center gap-3 mb-2">
        <span className={`w-2.5 h-2.5 rounded-full ${isOk ? "bg-zinc-400" : "bg-white ring-2 ring-white/20"}`} />
        <h2 className="text-sm font-semibold text-white font-mono uppercase tracking-wider">{label}</h2>
      </div>
      <p className="text-xs text-zinc-300 leading-relaxed max-w-3xl">
        {VERDICT_TEXT[highest] || VERDICT_TEXT.ok}
      </p>
    </div>
  );
}

export default function ReportPage() {
  const { scanId } = useParams();
  const [report, setReport] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [pdfError, setPdfError] = useState("");
  const [pdfLoading, setPdfLoading] = useState(false);

  useEffect(() => {
    let active = true;
    async function load() {
      setLoading(true);
      try {
        const r = await getReport(scanId);
        if (active) setReport(r);
      } catch (err) {
        if (active) setError(err.message);
      } finally {
        if (active) setLoading(false);
      }
    }
    load();
    return () => {
      active = false;
    };
  }, [scanId]);

  const handlePdf = async () => {
    setPdfError("");
    setPdfLoading(true);
    try {
      await downloadReportPdf(scanId);
    } catch (err) {
      setPdfError(err.message);
    } finally {
      setPdfLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="p-12 text-center text-zinc-500 font-mono text-xs">
        Loading audit report data…
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-6 rounded-lg border border-red-500/30 bg-brand-surface max-w-xl mx-auto my-12 text-xs text-red-400">
        <span className="font-semibold font-mono">Error loading report:</span> {error}
      </div>
    );
  }

  if (!report) {
    return (
      <div className="p-12 text-center text-zinc-500 font-mono text-xs">
        No report found for scan ID: {scanId}
      </div>
    );
  }

  const categories = report.categories || {};
  const findings = Object.values(categories).flat();

  const counts = {};
  let total = 0;
  for (const f of findings) {
    const sev = f.severity || "info";
    counts[sev] = (counts[sev] || 0) + 1;
    total += 1;
  }

  let highest = "ok";
  for (const { key } of SEVERITIES) {
    if ((counts[key] || 0) > 0) {
      highest = key;
      break;
    }
  }

  const hasFindings = Object.values(categories).some(
    (f) => Array.isArray(f) && f.length > 0
  );

  return (
    <div className="flex flex-col">
      {/* Breadcrumb */}
      <nav className="mb-6" aria-label="Breadcrumb">
        <ol className="flex items-center gap-2 text-xs font-mono">
          <li>
            <Link to="/" className="text-brand-muted hover:text-white transition-colors">Dashboard</Link>
          </li>
          <li className="text-zinc-600">/</li>
          <li className="text-white font-medium">Scan Report</li>
        </ol>
      </nav>

      {/* Header card */}
      <section className="p-6 sm:p-8 rounded-lg border border-brand-border bg-brand-surface mb-8">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="inline-flex items-center gap-2 mb-2">
              <span className="w-1.5 h-1.5 rounded-full bg-white" />
              <span className="text-[11px] font-mono tracking-wider uppercase text-brand-muted">Vulnerability Audit Report</span>
            </div>
            <h1 className="text-xl sm:text-2xl font-semibold tracking-tight text-white mb-2">
              Scan Summary
            </h1>
            <div className="text-xs text-brand-muted font-mono flex flex-wrap gap-x-4 gap-y-1">
              <span>Target: <code className="text-zinc-200 bg-brand-black px-1.5 py-0.5 rounded border border-brand-border">{report.targetUrl}</code></span>
              {report.parameters && report.parameters.length > 0 && (
                <span>Parameters: <code className="text-zinc-200 bg-brand-black px-1.5 py-0.5 rounded border border-brand-border">{report.parameters.join(", ")}</code></span>
              )}
              <span>Scan ID: <span className="text-zinc-400">{report.scanId}</span></span>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handlePdf}
              disabled={pdfLoading}
              className="inline-flex items-center justify-center px-4 py-2 text-xs font-medium text-black bg-white rounded border border-white hover:bg-zinc-200 transition-colors disabled:opacity-50"
            >
              {pdfLoading ? "Generating PDF…" : "Download PDF Report"}
            </button>
          </div>
        </div>

        {pdfError && (
          <p className="mt-3 text-xs text-red-400 font-mono" role="alert">
            PDF Export Error: {pdfError}
          </p>
        )}
      </section>

      {/* Risk Verdict */}
      <RiskVerdict highest={highest} />

      {/* Stats Matrix */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 mb-8">
        <div className="p-4 rounded-lg border border-brand-border bg-brand-surface">
          <span className="block text-[11px] font-mono text-zinc-500 uppercase tracking-wider">Total Findings</span>
          <span className="text-2xl font-semibold font-mono text-white mt-1 block">{total}</span>
        </div>
        <div className="p-4 rounded-lg border border-brand-border bg-brand-surface">
          <span className="block text-[11px] font-mono text-zinc-500 uppercase tracking-wider">Critical</span>
          <span className="text-2xl font-semibold font-mono text-white mt-1 block">{counts.critical || 0}</span>
        </div>
        <div className="p-4 rounded-lg border border-brand-border bg-brand-surface">
          <span className="block text-[11px] font-mono text-zinc-500 uppercase tracking-wider">High</span>
          <span className="text-2xl font-semibold font-mono text-zinc-300 mt-1 block">{counts.high || 0}</span>
        </div>
        <div className="p-4 rounded-lg border border-brand-border bg-brand-surface">
          <span className="block text-[11px] font-mono text-zinc-500 uppercase tracking-wider">Medium</span>
          <span className="text-2xl font-semibold font-mono text-zinc-400 mt-1 block">{counts.medium || 0}</span>
        </div>
        <div className="p-4 rounded-lg border border-brand-border bg-brand-surface">
          <span className="block text-[11px] font-mono text-zinc-500 uppercase tracking-wider">Low</span>
          <span className="text-2xl font-semibold font-mono text-zinc-500 mt-1 block">{counts.low || 0}</span>
        </div>
      </div>

      {/* Findings Table Section */}
      <section className="mb-8">
        <div className="flex items-center justify-between mb-4 pb-2 border-b border-brand-border">
          <h2 className="text-xs font-mono font-medium tracking-widest uppercase text-brand-muted">
            FINDINGS BY MODULE
          </h2>
          <span className="text-[11px] font-mono text-zinc-500">OWASP Coverage</span>
        </div>
        <VulnerabilityTable categories={categories} />
      </section>

      {/* Remediation Section */}
      <section className="p-6 rounded-lg border border-brand-border bg-brand-surface mb-8">
        <div className="mb-4 pb-2 border-b border-brand-border flex items-center justify-between">
          <h2 className="text-xs font-mono font-medium tracking-widest uppercase text-brand-muted">
            REMEDIATION GUIDELINES
          </h2>
          <span className="text-[11px] font-mono text-zinc-500">Security Engineering Guidance</span>
        </div>

        {hasFindings ? (
          <div className="divide-y divide-brand-border/60">
            {Object.entries(categories)
              .filter(([, f]) => Array.isArray(f) && f.length > 0)
              .map(([category]) => (
                <div key={category} className="py-4 first:pt-0 last:pb-0">
                  <h3 className="text-xs font-semibold text-white font-mono">{category}</h3>
                  <RemediationPanel category={category} />
                </div>
              ))}
          </div>
        ) : (
          <div className="p-4 text-center text-zinc-500 text-xs font-mono">
            No vulnerabilities detected. All baseline tests passed.
          </div>
        )}
      </section>

      <div className="text-center pt-2">
        <Link to="/scan" className="text-xs font-mono text-brand-muted hover:text-white underline transition-colors">
          ← Run another vulnerability scan
        </Link>
      </div>
    </div>
  );
}
