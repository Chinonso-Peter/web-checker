import { useState } from "react";
import { startScan } from "../api/apiClient.js";

// Supports both domains and localhost / IP addresses with optional ports and paths
const URL_PATTERN = /^(https?):\/\/([a-zA-Z0-9-._]+)(:\d+)?([/\w .?&=%-]*)?$/i;

export default function ScanInputForm({ onStarted }) {
  const [url, setUrl] = useState("");
  const [paramsText, setParamsText] = useState("");
  const [cookies, setCookies] = useState("");
  const [headers, setHeaders] = useState("");
  const [showAuthOptions, setShowAuthOptions] = useState(false);
  const [error, setError] = useState("");
  const [urlFieldError, setUrlFieldError] = useState(false);
  const [loading, setLoading] = useState(false);

  const triggerUrlError = (message) => {
    setError(message);
    setUrlFieldError(true);
  };

  const onSubmit = async (e) => {
    e.preventDefault();
    setUrlFieldError(false);
    setError("");

    const trimmed = url.trim();
    if (!URL_PATTERN.test(trimmed)) {
      triggerUrlError("INVALID PROTOCOL OR HOSTNAME (must start with http:// or https://)");
      return;
    }

    const parameters = paramsText
      .split(",")
      .map((p) => p.trim())
      .filter(Boolean)
      .slice(0, 20);

    setLoading(true);
    try {
      const res = await startScan(
        trimmed,
        parameters,
        cookies.trim() || undefined,
        headers.trim() || undefined
      );
      onStarted(res.scanId);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="p-6 sm:p-8 rounded-lg border border-brand-border bg-brand-surface" aria-labelledby="scan-config-title">
      <div className="flex items-center justify-between mb-6 pb-2 border-b border-brand-border">
        <h2 id="scan-config-title" className="text-xs font-mono font-medium tracking-widest uppercase text-brand-muted">
          AUDIT TARGET CONFIGURATION
        </h2>
        <span className="text-[11px] font-mono text-zinc-500">HTTP / HTTPS</span>
      </div>

      {error && (
        <div className="mb-6 p-3 rounded bg-red-500/10 border border-red-500/30 text-xs text-red-400 flex items-center gap-2" role="alert">
          <span aria-hidden="true">⚠</span>
          <span>{error}</span>
        </div>
      )}

      <form className="space-y-6" onSubmit={onSubmit}>
        <div>
          <label className="block text-xs font-mono font-medium text-zinc-300 uppercase tracking-wider mb-2" htmlFor="targetUrl">
            Target URL / Endpoint
          </label>
          <input
            id="targetUrl"
            name="targetUrl"
            className={`w-full h-10 px-3.5 rounded bg-brand-black border ${
              urlFieldError ? "border-red-500" : "border-brand-border"
            } text-white text-xs font-mono placeholder:text-zinc-600 focus:outline-none focus:border-zinc-400 transition-colors`}
            placeholder="http://localhost:8080/vulnerabilities/sqli/"
            value={url}
            onChange={(e) => {
              setUrl(e.target.value);
              setUrlFieldError(false);
              setError("");
            }}
            type="text"
            aria-invalid={urlFieldError}
            aria-describedby={urlFieldError ? "url-field-error" : undefined}
            autoComplete="url"
          />
          {urlFieldError && (
            <p className="mt-1.5 text-[11px] font-mono text-red-400 flex items-center gap-1" id="url-field-error" role="alert">
              <span aria-hidden="true">✕</span>
              Invalid protocol or hostname
            </p>
          )}
          {!urlFieldError && (url.includes("8080") || url.toLowerCase().includes("dvwa") || url.toLowerCase().includes("vulnerabilities")) && (
            <p className="mt-1.5 text-[11px] font-mono text-teal-400 flex items-center gap-1.5">
              <span>✓</span>
              <span>DVWA target detected — Automatic session handshake (low security) will be applied seamlessly.</span>
            </p>
          )}
        </div>

        <div>
          <label className="block text-xs font-mono font-medium text-zinc-300 uppercase tracking-wider mb-2" htmlFor="parameters">
            Parameter Names (Optional)
          </label>
          <textarea
            id="parameters"
            className="w-full min-h-[80px] p-3 rounded bg-brand-black border border-brand-border text-white text-xs font-mono placeholder:text-zinc-600 focus:outline-none focus:border-zinc-400 transition-colors resize-y"
            placeholder="id, name, q, search, Submit..."
            rows="2"
            value={paramsText}
            onChange={(e) => setParamsText(e.target.value)}
          />
          <p className="mt-1.5 text-[11px] text-zinc-500 font-mono">
            Comma-separated parameters to inject. Leave blank to automatically crawl all inputs and form fields.
          </p>
        </div>

        {/* Collapsible Authentication & Session Header Settings */}
        <div className="pt-1">
          <button
            type="button"
            onClick={() => setShowAuthOptions(!showAuthOptions)}
            className="text-xs font-mono text-zinc-400 hover:text-white flex items-center gap-2 transition-colors group"
          >
            <span className="text-[10px] text-zinc-500 group-hover:text-white transition-colors">
              {showAuthOptions ? "▼" : "▶"}
            </span>
            <span>Authentication &amp; Session Cookies (Optional)</span>
            {cookies.trim() && (
              <span className="px-1.5 py-0.2 rounded text-[10px] bg-teal-500/20 text-teal-300 border border-teal-500/30">
                Cookies active
              </span>
            )}
          </button>

          {showAuthOptions && (
            <div className="mt-3 p-4 rounded-lg bg-brand-black border border-brand-border space-y-4">
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="block text-xs font-mono font-medium text-zinc-300 uppercase tracking-wider" htmlFor="cookies">
                    Session Cookies
                  </label>
                  <span className="text-[10px] font-mono text-teal-400">Essential for DVWA</span>
                </div>
                <input
                  id="cookies"
                  name="cookies"
                  type="text"
                  className="w-full h-10 px-3.5 rounded bg-brand-surface border border-brand-border text-white text-xs font-mono placeholder:text-zinc-600 focus:outline-none focus:border-zinc-400"
                  placeholder="PHPSESSID=abc123xyz456; security=low"
                  value={cookies}
                  onChange={(e) => setCookies(e.target.value)}
                />
                <p className="mt-1.5 text-[11px] text-zinc-500 font-mono">
                  For DVWA: copy your session cookie from DevTools (F12 → Storage/Application → Cookies) to audit behind the login.
                </p>
              </div>

              <div>
                <label className="block text-xs font-mono font-medium text-zinc-300 uppercase tracking-wider mb-1.5" htmlFor="customHeaders">
                  Custom HTTP Headers
                </label>
                <textarea
                  id="customHeaders"
                  name="customHeaders"
                  rows="2"
                  className="w-full p-3 rounded bg-brand-surface border border-brand-border text-white text-xs font-mono placeholder:text-zinc-600 focus:outline-none focus:border-zinc-400 resize-y"
                  placeholder="Authorization: Bearer <token>&#10;X-Custom-Header: value"
                  value={headers}
                  onChange={(e) => setHeaders(e.target.value)}
                />
              </div>
            </div>
          )}
        </div>

        <div className="pt-2 flex items-center justify-between border-t border-brand-border/60">
          <span className="text-[11px] font-mono text-zinc-500">
            OWASP Top 10 Coverage Engine
          </span>
          <button
            type="submit"
            disabled={loading}
            className={`relative overflow-hidden inline-flex items-center justify-center px-6 py-2.5 text-xs font-mono font-medium rounded transition-all duration-300 ${
              loading
                ? "bg-zinc-950 border border-teal-500/60 text-teal-300 animate-scan-glow cursor-wait"
                : "bg-white text-black border border-white hover:bg-zinc-200"
            }`}
          >
            {loading && (
              <>
                {/* Horizontal Sweeping Laser Beam */}
                <span className="absolute inset-0 w-full h-full bg-gradient-to-r from-transparent via-teal-400/35 to-transparent animate-scan-beam pointer-events-none" />

                {/* Rotating Radar Target Reticle */}
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
              {loading ? "SCANNING TARGET…" : "Initiate Audit Scan"}
            </span>
          </button>
        </div>
      </form>
    </section>
  );
}
