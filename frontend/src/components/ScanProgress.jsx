import { useEffect, useState } from "react";
import { checkScanStatus } from "../api/apiClient.js";

export default function ScanProgress({ scanId }) {
  const [status, setStatus] = useState("pending");

  useEffect(() => {
    if (!scanId) return;
    let active = true;
    const poll = async () => {
      try {
        const res = await checkScanStatus(scanId);
        if (active) setStatus(res.status);
      } catch {
        /* ignore transient errors */
      }
    };
    poll();
    const id = setInterval(poll, 2000);
    return () => {
      active = false;
      clearInterval(id);
    };
  }, [scanId]);

  if (!scanId) return null;

  const statusLabels = {
    pending: "Queued",
    running: "Scanning",
    completed: "Completed",
    failed: "Failed"
  };

  const statusStyles = {
    pending: "bg-zinc-900 border-zinc-800 text-zinc-400",
    running: "bg-zinc-900 border-zinc-700 text-white",
    completed: "bg-zinc-900 border-zinc-700 text-white",
    failed: "bg-zinc-900 border-red-800 text-red-400"
  };

  return (
    <div className="p-5 rounded-lg border border-brand-border bg-brand-surface flex items-center justify-between">
      <div className="flex flex-col gap-1">
        <span className="text-[11px] font-mono uppercase text-brand-muted tracking-wider">Active Audit Status</span>
        <span className="text-xs text-zinc-400 font-mono">ID: {scanId}</span>
      </div>
      <div className={`inline-flex items-center gap-2 px-3 py-1 rounded border text-xs font-mono font-medium ${statusStyles[status] || statusStyles.pending}`}>
        {status === "running" && <span className="w-1.5 h-1.5 rounded-full bg-white animate-pulse" />}
        {statusLabels[status] || status}
      </div>
    </div>
  );
}
