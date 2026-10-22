import { BrowserRouter, Routes, Route, Link, useLocation } from "react-router-dom";
import { getAuth } from "./api/apiClient.js";
import DashboardPage from "./pages/DashboardPage.jsx";
import RegisterPage from "./pages/RegisterPage.jsx";
import LoginPage from "./pages/LoginPage.jsx";
import ScanPage from "./pages/ScanPage.jsx";
import ReportPage from "./pages/ReportPage.jsx";
import ProfilePage from "./pages/ProfilePage.jsx";
import ForgotPasswordPage from "./pages/ForgotPasswordPage.jsx";
import ResetPasswordPage from "./pages/ResetPasswordPage.jsx";
import VerifyEmailPage from "./pages/VerifyEmailPage.jsx";
import UserDropdown from "./components/UserDropdown.jsx";
import ThemeToggle from "./components/ThemeToggle.jsx";

function UnverifiedBanner() {
  const auth = getAuth();
  const { pathname } = useLocation();

  if (!auth || auth.isVerified !== false || pathname === "/verify-email") {
    return null;
  }

  return (
    <div className="bg-amber-500/10 border-b border-amber-500/30 text-amber-300 text-xs py-2 px-6">
      <div className="max-w-6xl mx-auto flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span>⚠</span>
          <span>
            Your email (<span className="font-mono">{auth.email}</span>) is not verified. Please check your inbox for the verification token.
          </span>
        </div>
        <Link
          to="/verify-email"
          className="ml-4 font-medium underline hover:text-white transition-colors"
        >
          Verify Now →
        </Link>
      </div>
    </div>
  );
}

function Navbar() {
  const { pathname } = useLocation();
  const auth = getAuth();

  return (
    <header className="border-b border-brand-border bg-brand-black/90 sticky top-0 z-50 backdrop-blur-sm" data-purpose="app-header">
      <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
        {/* App Identity / Brand Logo */}
        <Link to="/" className="flex items-center gap-2.5 group focus:outline-none focus-visible:ring-1 focus-visible:ring-white">
          <div className="w-8 h-8 rounded border border-brand-border bg-brand-surface flex items-center justify-center transition-colors group-hover:border-zinc-500">
            {/* Minimalist Security Shield Icon */}
            <svg className="w-4 h-4 text-white" fill="none" stroke="currentColor" strokeWidth="1.8" viewBox="0 0 24 24">
              <path d="M12 3.25L5 6.25v6.5c0 5 3.5 8.75 7 10 3.5-1.25 7-5 7-10v-6.5l-7-3zM12 9v6m-3-3h6" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </div>
          <span className="font-semibold text-sm tracking-tight text-white flex items-center gap-1.5">
            <span>Web</span>
            <span className="text-brand-muted font-mono font-medium text-xs">/</span>
            <span className="font-normal text-zinc-300">Checker</span>
          </span>
        </Link>

        {/* Navigation Links */}
        <nav className="flex items-center gap-1 sm:gap-2" data-purpose="main-nav">
          <Link
            to="/"
            className={`px-3 py-1.5 text-xs font-medium transition-colors rounded ${
              pathname === "/"
                ? "text-white bg-brand-surface"
                : "text-brand-muted hover:text-white hover:bg-brand-surface"
            }`}
          >
            Dashboard
          </Link>
          <Link
            to="/scan"
            className={`px-3 py-1.5 text-xs font-medium transition-colors rounded ${
              pathname.startsWith("/scan")
                ? "text-white bg-brand-surface"
                : "text-brand-muted hover:text-white hover:bg-brand-surface"
            }`}
          >
            New Scan
          </Link>

          {auth ? (
            <>
              <span aria-hidden="true" className="h-4 w-px bg-brand-border mx-1" />
              <UserDropdown />
            </>
          ) : (
            <>
              <span aria-hidden="true" className="h-4 w-px bg-brand-border mx-1" />
              <Link
                to="/register"
                className={`px-3 py-1.5 text-xs font-medium transition-colors rounded ${
                  pathname === "/register"
                    ? "text-white bg-brand-surface"
                    : "text-zinc-300 hover:text-white hover:bg-brand-surface"
                }`}
              >
                Register
              </Link>
              <Link
                to="/login"
                className="px-3.5 py-1.5 text-xs font-medium bg-white text-black rounded hover:bg-zinc-200 transition-colors focus:ring-1 focus:ring-zinc-400"
              >
                Login
              </Link>
            </>
          )}

          <span aria-hidden="true" className="h-4 w-px bg-brand-border mx-1" />
          <ThemeToggle />
        </nav>
      </div>
    </header>
  );
}

function Footer() {
  return (
    <footer className="border-t border-brand-border py-6 mt-12 bg-brand-black" data-purpose="app-footer">
      <div className="max-w-6xl mx-auto px-6 flex flex-col sm:flex-row items-center justify-between text-xs text-zinc-600 gap-3">
        <div className="flex items-center gap-2">
          <span className="font-mono text-zinc-400">Web Checker</span>
          <span>— Security audit platform</span>
        </div>
        <div className="font-mono text-[11px] text-zinc-600">
          OWASP Top 10 Coverage Engine
        </div>
      </div>
    </footer>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-brand-black flex flex-col justify-between selection:bg-white selection:text-black">
        <Navbar />
        <UnverifiedBanner />
        <main className="flex-1 max-w-6xl w-full mx-auto px-6 py-10 md:py-14 flex flex-col">
          <Routes>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/register" element={<RegisterPage />} />
            <Route path="/login" element={<LoginPage />} />
            <Route path="/forgot-password" element={<ForgotPasswordPage />} />
            <Route path="/reset-password" element={<ResetPasswordPage />} />
            <Route path="/verify-email" element={<VerifyEmailPage />} />
            <Route path="/scan" element={<ScanPage />} />
            <Route path="/report/:scanId" element={<ReportPage />} />
            <Route path="/profile" element={<ProfilePage />} />
            <Route path="*" element={<DashboardPage />} />
          </Routes>
        </main>
        <Footer />
      </div>
    </BrowserRouter>
  );
}
