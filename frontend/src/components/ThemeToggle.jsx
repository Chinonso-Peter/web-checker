import { useState, useEffect } from "react";

export default function ThemeToggle() {
  const [theme, setTheme] = useState(() => {
    try {
      const saved = localStorage.getItem("webCheckerTheme");
      if (saved === "light" || saved === "dark") return saved;
      return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
    } catch {
      return "dark";
    }
  });

  useEffect(() => {
    const root = document.documentElement;
    if (theme === "light") {
      root.classList.add("light");
      root.classList.remove("dark");
    } else {
      root.classList.add("dark");
      root.classList.remove("light");
    }
    try {
      localStorage.setItem("webCheckerTheme", theme);
    } catch {}
  }, [theme]);

  const toggleTheme = () => {
    setTheme((prev) => (prev === "dark" ? "light" : "dark"));
  };

  return (
    <button
      type="button"
      onClick={toggleTheme}
      aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
      title={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
      className="w-8 h-8 rounded border border-brand-border bg-brand-surface hover:bg-brand-hover text-brand-muted hover:text-white flex items-center justify-center transition-colors focus:outline-none focus:ring-1 focus:ring-zinc-400 shrink-0"
    >
      {theme === "dark" ? (
        /* Sun Icon (Click to activate Light Mode) */
        <svg className="w-4 h-4 text-amber-300 transition-transform hover:rotate-45" fill="none" stroke="currentColor" strokeWidth="1.8" viewBox="0 0 24 24">
          <circle cx="12" cy="12" r="4" />
          <path d="M12 2v2m0 16v2M4.93 4.93l1.41 1.41m11.32 11.32l1.41 1.41M2 12h2m16 0h2M6.34 17.66l-1.41 1.41m14.14-14.14l-1.41 1.41" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      ) : (
        /* Moon Icon (Click to activate Dark Mode) */
        <svg className="w-4 h-4 text-slate-700 transition-transform hover:-rotate-12" fill="none" stroke="currentColor" strokeWidth="1.8" viewBox="0 0 24 24">
          <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      )}
    </button>
  );
}
