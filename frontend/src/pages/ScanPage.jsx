import { useState } from "react";
import { useNavigate } from "react-router-dom";
import ScanInputForm from "../components/ScanInputForm.jsx";
import ScanProgress from "../components/ScanProgress.jsx";

const COVERAGE = [
  "SQL Injection",
  "Cross-Site Scripting",
  "Broken Access Control",
  "Cryptographic Failures",
  "Authentication Failures",
];

const SEVERITY = [
  { key: "critical", label: "Critical", border: "border-zinc-700", dot: "bg-white" },
  { key: "high", label: "High", border: "border-zinc-800", dot: "bg-zinc-400" },
  { key: "medium", label: "Medium", border: "border-zinc-800", dot: "bg-zinc-600" },
  { key: "low", label: "Low", border: "border-zinc-850", dot: "bg-zinc-700" },
];

export default function ScanPage() {
  const [scanId, setScanId] = useState(null);
  const navigate = useNavigate();

  const handleStarted = (id) => {
    setScanId(id);
    navigate(`/report/${id}`);
  };

  return (
    <div className="flex flex-col">
      {/* Breadcrumb */}
      <nav className="mb-6" aria-label="Breadcrumb">
        <ol className="flex items-center gap-2 text-xs font-mono">
          <li>
            <a href="/" className="text-brand-muted hover:text-white transition-colors">Dashboard</a>
          </li>
          <li className="text-zinc-600">/</li>
          <li className="text-white font-medium">New Scan</li>
        </ol>
      </nav>

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-baseline justify-between gap-2 mb-8 pb-4 border-b border-brand-border">
        <div>
          <h1 className="text-xl sm:text-2xl font-semibold tracking-tight text-white">
            Scan Configuration
          </h1>
          <p className="text-xs text-brand-muted mt-1">Configure target endpoint and parameters for automated vulnerability testing</p>
        </div>
        <span className="text-[11px] font-mono uppercase tracking-wider text-zinc-500">
          Environment: Target Active
        </span>
      </div>

      {/* Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        <div className="lg:col-span-8 flex flex-col gap-6">
          <ScanInputForm onStarted={handleStarted} />
          <ScanProgress scanId={scanId} />
        </div>

        <aside className="lg:col-span-4 flex flex-col gap-6">
          <div className="p-6 rounded-lg border border-brand-border bg-brand-surface">
            <h3 className="text-xs font-mono font-medium tracking-widest uppercase text-brand-muted mb-4 pb-2 border-b border-brand-border">
              SCAN PROFILE
            </h3>

            <div className="mb-6">
              <span className="block text-[11px] font-mono text-zinc-500 uppercase tracking-wider mb-3">Coverage Modules</span>
              <ul className="space-y-2">
                {COVERAGE.map((c) => (
                  <li key={c} className="flex items-center gap-2.5 text-xs text-zinc-300">
                    <span className="w-4 h-4 rounded border border-brand-border bg-brand-subtle flex items-center justify-center text-white text-[10px] font-mono">✓</span>
                    {c}
                  </li>
                ))}
              </ul>
            </div>

            <div className="mb-6">
              <span className="block text-[11px] font-mono text-zinc-500 uppercase tracking-wider mb-3">Severity Classification</span>
              <div className="flex flex-wrap gap-2 font-mono text-xs">
                {SEVERITY.map((s) => (
                  <div key={s.key} className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-zinc-900 border ${s.border} text-zinc-300 text-xs`}>
                    <span className={`w-1.5 h-1.5 rounded-full ${s.dot}`} />
                    <span>{s.label}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="pt-4 border-t border-brand-border/60">
              <span className="block text-[11px] font-mono text-zinc-500 uppercase tracking-wider mb-1">Execution Note</span>
              <p className="text-xs text-brand-muted leading-relaxed">
                Leave parameter names empty to crawl discovered forms automatically. Scans use non-destructive payloads.
              </p>
            </div>
          </div>
        </aside>
      </div>
    </div>
  );
}
