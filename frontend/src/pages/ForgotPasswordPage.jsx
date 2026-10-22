import { useState, useEffect } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { forgotPassword, forgotUsername } from "../api/apiClient.js";

export default function ForgotPasswordPage() {
  const [searchParams] = useSearchParams();
  const initialTab = searchParams.get("tab") === "username" ? "username" : "password";

  const [activeTab, setActiveTab] = useState(initialTab);
  const [email, setEmail] = useState("");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const tabParam = searchParams.get("tab");
    if (tabParam === "username") {
      setActiveTab("username");
    }
  }, [searchParams]);

  const onSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    if (!email.trim()) {
      setError("Email is required");
      return;
    }

    setLoading(true);
    try {
      if (activeTab === "username") {
        const res = await forgotUsername(email.trim());
        setSuccess(res.message || "If that email is registered, your username reminder has been sent to your Gmail inbox.");
      } else {
        await forgotPassword(email.trim());
        setSuccess("If that email is registered, a password reset link and token have been sent to your Gmail inbox.");
      }
      setEmail("");
    } catch (err) {
      setError(err.message || "Failed to process request.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex-1 flex items-center justify-center py-10">
      <div className="w-full max-w-sm p-6 sm:p-8 rounded-lg border border-brand-border bg-brand-surface">
        <div className="mb-6">
          <span className="text-[11px] font-mono tracking-wider uppercase text-brand-muted block mb-1">
            Account Recovery
          </span>
          <h1 className="text-xl font-semibold tracking-tight text-white">
            {activeTab === "username" ? "Recover Username" : "Forgot Password"}
          </h1>
          <p className="text-xs text-brand-muted mt-1">
            {activeTab === "username"
              ? "Receive your registered username via Gmail"
              : "Enter your registered email to receive a reset token"}
          </p>
        </div>

        {/* Tab switchers */}
        <div className="flex gap-2 border-b border-brand-border mb-5">
          <button
            type="button"
            className={`pb-2 text-xs font-medium font-mono border-b-2 transition-colors ${
              activeTab === "password"
                ? "border-white text-white"
                : "border-transparent text-brand-muted hover:text-white"
            }`}
            onClick={() => {
              setActiveTab("password");
              setError("");
              setSuccess("");
            }}
          >
            Reset Password
          </button>
          <button
            type="button"
            className={`pb-2 text-xs font-medium font-mono border-b-2 transition-colors ${
              activeTab === "username"
                ? "border-white text-white"
                : "border-transparent text-brand-muted hover:text-white"
            }`}
            onClick={() => {
              setActiveTab("username");
              setError("");
              setSuccess("");
            }}
          >
            Find Username
          </button>
        </div>

        {activeTab === "username" && (
          <div className="mb-4 p-3 rounded bg-zinc-900/80 border border-zinc-800 text-[11px] text-zinc-300 font-mono">
            💡 <strong className="text-white">Did you know?</strong> If you remember your password, you can log in directly using your email address instead of your username!
          </div>
        )}

        {error && (
          <div
            className="mb-4 p-3 rounded bg-red-500/10 border border-red-500/30 text-xs text-red-400 font-mono flex items-center gap-2"
            role="alert"
          >
            <span aria-hidden="true">⚠</span>
            <span>{error}</span>
          </div>
        )}

        {success && (
          <div className="mb-4 p-3 rounded bg-zinc-900 border border-zinc-700 text-xs text-white font-mono flex items-center gap-2">
            <span>✓</span>
            <span>{success}</span>
          </div>
        )}

        <form onSubmit={onSubmit} className="space-y-4">
          <div>
            <label
              className="block text-xs font-mono font-medium text-zinc-300 uppercase tracking-wider mb-2"
              htmlFor="email"
            >
              Registered Email Address
            </label>
            <input
              id="email"
              name="email"
              type="email"
              className="w-full h-10 px-3.5 rounded bg-brand-black border border-brand-border text-white text-xs font-mono placeholder:text-zinc-600 focus:outline-none focus:border-zinc-400 transition-colors"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              autoComplete="email"
              placeholder="hello@gmail.com"
              disabled={loading}
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full h-10 inline-flex items-center justify-center px-4 text-xs font-medium text-black bg-white rounded border border-white hover:bg-zinc-200 transition-colors disabled:opacity-50 mt-2"
          >
            {loading
              ? "Sending…"
              : activeTab === "username"
              ? "Send Username Reminder"
              : "Send Reset Link"}
          </button>
        </form>

        <p className="mt-6 pt-4 border-t border-brand-border/60 text-center text-xs text-brand-muted space-x-2">
          {activeTab === "password" ? (
            <>
              <span>Have a token?</span>
              <Link to="/reset-password" className="text-white hover:underline font-medium">
                Enter Token
              </Link>
              <span>·</span>
            </>
          ) : null}
          <Link to="/login" className="text-white hover:underline font-medium">
            Back to Sign In
          </Link>
        </p>
      </div>
    </div>
  );
}
