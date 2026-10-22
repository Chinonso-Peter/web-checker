import { useState, useEffect } from "react";
import { useSearchParams, Link, useNavigate } from "react-router-dom";
import { resetPassword } from "../api/apiClient.js";

export default function ResetPasswordPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const urlToken = searchParams.get("token") || "";

  const [token, setToken] = useState(urlToken);
  const [form, setForm] = useState({ password: "", confirmPassword: "" });
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (urlToken) {
      setToken(urlToken);
    }
  }, [urlToken]);

  const onChange = (e) => {
    const { name, value } = e.target;
    setForm((prev) => ({ ...prev, [name]: value }));
    if (error) setError("");
    if (success) setSuccess("");
  };

  const onSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    const activeToken = token.trim();
    if (!activeToken) {
      setError("Please provide a password reset token.");
      return;
    }

    if (form.password.length < 6) {
      setError("Password must be at least 6 characters.");
      return;
    }
    if (form.password !== form.confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    setLoading(true);
    try {
      await resetPassword(activeToken, form.password);
      setSuccess("Password updated successfully! Redirecting to login…");
      setForm({ password: "", confirmPassword: "" });
      setTimeout(() => navigate("/login"), 2000);
    } catch (err) {
      setError(err.message || "Failed to reset password.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex-1 flex items-center justify-center py-10">
      <div className="w-full max-w-sm p-6 sm:p-8 rounded-lg border border-brand-border bg-brand-surface">
        <div className="mb-6">
          <span className="text-[11px] font-mono tracking-wider uppercase text-brand-muted block mb-1">
            Credential Recovery
          </span>
          <h1 className="text-xl font-semibold tracking-tight text-white">Reset Password</h1>
          <p className="text-xs text-brand-muted mt-1">
            {urlToken
              ? "Token detected from link. Enter your new password below."
              : "Paste the reset token received in your Gmail to update credentials."}
          </p>
        </div>

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
              htmlFor="token"
            >
              Reset Token
            </label>
            <input
              id="token"
              name="token"
              type="text"
              className="w-full h-10 px-3.5 rounded bg-brand-black border border-brand-border text-white text-xs font-mono placeholder:text-zinc-600 focus:outline-none focus:border-zinc-400 transition-colors"
              value={token}
              onChange={(e) => {
                setToken(e.target.value);
                if (error) setError("");
              }}
              required
              placeholder="Paste token from email"
              disabled={loading}
            />
            {urlToken && (
              <span className="text-[11px] text-teal-400 font-mono mt-1 block">
                ✓ Token loaded from link
              </span>
            )}
          </div>

          <div>
            <label
              className="block text-xs font-mono font-medium text-zinc-300 uppercase tracking-wider mb-2"
              htmlFor="password"
            >
              New Password
            </label>
            <input
              id="password"
              name="password"
              type="password"
              className="w-full h-10 px-3.5 rounded bg-brand-black border border-brand-border text-white text-xs font-mono placeholder:text-zinc-600 focus:outline-none focus:border-zinc-400 transition-colors"
              value={form.password}
              onChange={onChange}
              required
              autoComplete="new-password"
              minLength={6}
              placeholder="Minimum 6 characters"
              disabled={loading}
            />
          </div>

          <div>
            <label
              className="block text-xs font-mono font-medium text-zinc-300 uppercase tracking-wider mb-2"
              htmlFor="confirmPassword"
            >
              Confirm Password
            </label>
            <input
              id="confirmPassword"
              name="confirmPassword"
              type="password"
              className="w-full h-10 px-3.5 rounded bg-brand-black border border-brand-border text-white text-xs font-mono placeholder:text-zinc-600 focus:outline-none focus:border-zinc-400 transition-colors"
              value={form.confirmPassword}
              onChange={onChange}
              required
              autoComplete="new-password"
              placeholder="Re-enter password"
              disabled={loading}
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full h-10 inline-flex items-center justify-center px-4 text-xs font-medium text-black bg-white rounded border border-white hover:bg-zinc-200 transition-colors disabled:opacity-50 mt-2"
          >
            {loading ? "Updating Password…" : "Update Password"}
          </button>
        </form>

        <p className="mt-6 pt-4 border-t border-brand-border/60 text-center text-xs text-brand-muted">
          Need a token?{" "}
          <Link to="/forgot-password" className="text-white hover:underline font-medium">
            Request new reset link
          </Link>
          {" · "}
          <Link to="/login" className="text-white hover:underline font-medium">
            Sign In
          </Link>
        </p>
      </div>
    </div>
  );
}
