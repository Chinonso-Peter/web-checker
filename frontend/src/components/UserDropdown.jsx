import { useState, useRef, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import { getAuth, clearAuth, logoutUser } from "../api/apiClient.js";

export default function UserDropdown() {
  const [open, setOpen] = useState(false);
  const dropdownRef = useRef(null);
  const navigate = useNavigate();
  const auth = getAuth();

  const handleLogout = async () => {
    try {
      await logoutUser();
    } catch {
      /* ignore network errors */
    }
    clearAuth();
    navigate("/");
    setOpen(false);
  };

  useEffect(() => {
    function handleClickOutside(e) {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  if (!auth) return null;

  const initial = auth.username?.charAt(0).toUpperCase() || "U";

  return (
    <div className="relative" ref={dropdownRef}>
      <button
        type="button"
        className="flex items-center gap-2 px-2.5 py-1 text-xs font-medium text-zinc-300 hover:text-white rounded border border-brand-border bg-brand-surface hover:border-zinc-500 transition-colors focus:outline-none"
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        aria-haspopup="true"
        aria-label="User account menu"
      >
        <span className="w-5 h-5 rounded bg-zinc-800 text-white font-semibold text-[10px] flex items-center justify-center">
          {initial}
        </span>
        <span className="font-mono text-xs">{auth.username}</span>
        <svg
          className={`w-3 h-3 text-zinc-500 transition-transform ${open ? "rotate-180" : ""}`}
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          viewBox="0 0 24 24"
        >
          <path d="m6 9 6 6 6-6" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </button>

      {open && (
        <div className="absolute right-0 mt-1.5 min-w-[200px] bg-brand-surface border border-brand-border rounded-lg shadow-xl p-1.5 z-50">
          <div className="px-3 py-2 border-b border-brand-border mb-1">
            <span className="block font-semibold text-xs text-white">@{auth.username}</span>
            {auth.email && <span className="block text-[11px] font-mono text-zinc-500 truncate">{auth.email}</span>}
          </div>
          <Link
            to="/profile"
            className="flex items-center gap-2 px-3 py-1.5 text-xs text-zinc-300 hover:text-white hover:bg-brand-subtle rounded transition-colors"
            onClick={() => setOpen(false)}
          >
            <svg className="w-3.5 h-3.5 text-zinc-400" fill="none" stroke="currentColor" strokeWidth="1.8" viewBox="0 0 24 24">
              <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
              <circle cx="12" cy="7" r="4" />
            </svg>
            Security Profile
          </Link>
          <Link
            to="/scan"
            className="flex items-center gap-2 px-3 py-1.5 text-xs text-zinc-300 hover:text-white hover:bg-brand-subtle rounded transition-colors"
            onClick={() => setOpen(false)}
          >
            <svg className="w-3.5 h-3.5 text-zinc-400" fill="none" stroke="currentColor" strokeWidth="1.8" viewBox="0 0 24 24">
              <circle cx="12" cy="12" r="10" />
              <line x1="12" y1="8" x2="12" y2="12" />
              <line x1="12" y1="16" x2="12.01" y2="16" />
            </svg>
            Audit Center
          </Link>
          <div className="my-1 border-t border-brand-border" />
          <button
            type="button"
            className="w-full text-left flex items-center gap-2 px-3 py-1.5 text-xs text-red-400 hover:text-red-300 hover:bg-red-500/10 rounded transition-colors"
            onClick={handleLogout}
          >
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth="1.8" viewBox="0 0 24 24">
              <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
              <polyline points="16 17 21 12 16 7" />
              <line x1="21" y1="12" x2="9" y2="12" />
            </svg>
            Sign Out
          </button>
        </div>
      )}
    </div>
  );
}
