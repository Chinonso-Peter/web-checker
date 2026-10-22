import { useState, useEffect } from "react";
import { useSearchParams, useLocation, Link, useNavigate } from "react-router-dom";
import { verifyEmail, resendVerification, getAuth, setAuth } from "../api/apiClient.js";

export default function VerifyEmailPage() {
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const urlToken = searchParams.get("token") || "";

  const auth = getAuth();
  const initialEmail = location.state?.email || auth?.email || searchParams.get("email") || "";
  const initialTokenSent = Boolean(location.state?.tokenSent || urlToken);

  const [token, setToken] = useState(urlToken);
  const [email, setEmail] = useState(initialEmail);
  const [hasSentToken, setHasSentToken] = useState(initialTokenSent);
  const [customEmailMode, setCustomEmailMode] = useState(!initialEmail);

  const [loading, setLoading] = useState(false);
  const [resendLoading, setResendLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [resendMessage, setResendMessage] = useState("");
  const [resendError, setResendError] = useState("");

  const executeVerify = async (tokenToVerify) => {
    if (!tokenToVerify) {
      setError("Please provide a verification token.");
      return;
    }

    setLoading(true);
    setError("");
    setSuccess("");

    try {
      const res = await verifyEmail(tokenToVerify);
      setSuccess(res.message || "Email verified successfully!");

      // If user is currently logged in, update their local auth record
      const currentAuth = getAuth();
      if (currentAuth) {
        setAuth({ ...currentAuth, isVerified: true });
      }

      setTimeout(() => {
        navigate(currentAuth ? "/scan" : "/login");
      }, 2500);
    } catch (err) {
      setError(err.message || "Email verification failed.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (urlToken) {
      setToken(urlToken);
      executeVerify(urlToken);
    }
  }, [urlToken]);

  const handleSubmit = (e) => {
    e.preventDefault();
    executeVerify(token.trim());
  };

  const handleResend = async (e) => {
    if (e && e.preventDefault) e.preventDefault();
    setResendError("");
    setResendMessage("");

    const targetEmail = email.trim();
    if (!targetEmail) {
      setResendError("Please enter your email address.");
      return;
    }

    setResendLoading(true);
    try {
      const res = await resendVerification(targetEmail);
      setResendMessage(res.message || "Verification email sent! Please check your inbox.");
      setHasSentToken(true);
    } catch (err) {
      setResendError(err.message || "Failed to send verification token.");
    } finally {
      setResendLoading(false);
    }
  };

  return (
    <div className="flex-1 flex items-center justify-center py-10">
      <div className="w-full max-w-md p-6 sm:p-8 rounded-lg border border-brand-border bg-brand-surface">
        <div className="mb-6">
          <span className="text-[11px] font-mono tracking-wider uppercase text-teal-400 block mb-1">
            Account Activation
          </span>
          <h1 className="text-xl font-semibold tracking-tight text-white">Verify Your Email</h1>
          <p className="text-xs text-brand-muted mt-1">
            {email && hasSentToken ? (
              <>
                A verification token was sent to <span className="text-zinc-200 font-mono font-medium">{email}</span>. Enter it below to activate your account.
              </>
            ) : email ? (
              <>
                Confirm your account for <span className="text-zinc-200 font-mono font-medium">{email}</span> by submitting your verification token.
              </>
            ) : (
              "Confirm your email address to enable all security scanning capabilities."
            )}
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
          <div className="mb-4 p-3 rounded bg-teal-500/10 border border-teal-500/30 text-xs text-teal-300 font-mono flex items-center gap-2">
            <span>✓</span>
            <span>{success} Redirecting…</span>
          </div>
        )}

        {/* Verification Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label
              className="block text-xs font-mono font-medium text-zinc-300 uppercase tracking-wider mb-2"
              htmlFor="verificationToken"
            >
              Verification Token
            </label>
            <input
              id="verificationToken"
              name="verificationToken"
              type="text"
              className="w-full h-10 px-3.5 rounded bg-brand-black border border-brand-border text-white text-xs font-mono placeholder:text-zinc-600 focus:outline-none focus:border-zinc-400 transition-colors"
              value={token}
              onChange={(e) => {
                setToken(e.target.value);
                if (error) setError("");
              }}
              required
              placeholder="Paste verification token from email"
              disabled={loading}
              autoFocus
            />
            {urlToken && (
              <span className="text-[11px] text-teal-400 font-mono mt-1 block">
                ✓ Token loaded from email link
              </span>
            )}
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full h-10 inline-flex items-center justify-center px-4 text-xs font-medium text-black bg-white rounded border border-white hover:bg-zinc-200 transition-colors disabled:opacity-50 mt-2"
          >
            {loading ? "Verifying Token…" : "Confirm Verification"}
          </button>
        </form>

        {/* Resend Verification Section */}
        <div className="mt-8 pt-6 border-t border-brand-border">
          <h2 className="text-xs font-semibold text-zinc-300 mb-1">
            {hasSentToken ? "Didn't receive the email?" : "Need a verification token?"}
          </h2>
          <p className="text-[11px] text-brand-muted mb-3">
            Tokens expire in 24 hours. Click below to {hasSentToken ? "resend" : "send"} a verification token to your inbox.
          </p>

          {resendMessage && (
            <div className="mb-3 p-2.5 rounded bg-zinc-900 border border-zinc-700 text-xs text-white font-mono flex items-center gap-2">
              <span>✓</span>
              <span>{resendMessage}</span>
            </div>
          )}

          {resendError && (
            <div className="mb-3 p-2.5 rounded bg-red-500/10 border border-red-500/30 text-xs text-red-400 font-mono flex items-center gap-2">
              <span>⚠</span>
              <span>{resendError}</span>
            </div>
          )}

          {/* If email is already known, do not force the user to type it in again! */}
          {!customEmailMode && email ? (
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3 rounded bg-brand-black border border-brand-border">
              <div className="min-w-0">
                <span className="text-[10px] font-mono text-zinc-500 uppercase tracking-wider block">Registered Email</span>
                <span className="text-xs font-mono text-zinc-200 font-medium truncate block">{email}</span>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <button
                  type="button"
                  onClick={handleResend}
                  disabled={resendLoading}
                  className="h-8 px-3.5 text-xs font-medium bg-zinc-800 text-zinc-200 border border-brand-border rounded hover:bg-zinc-700 hover:text-white transition-colors disabled:opacity-50"
                >
                  {resendLoading ? "Sending…" : hasSentToken ? "Resend" : "Send"}
                </button>
                <button
                  type="button"
                  onClick={() => setCustomEmailMode(true)}
                  className="text-[11px] text-brand-muted hover:text-white underline font-mono px-1"
                  title="Use a different email address"
                >
                  Edit
                </button>
              </div>
            </div>
          ) : (
            <form onSubmit={handleResend} className="flex gap-2">
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="Enter your email address"
                className="flex-1 h-9 px-3 rounded bg-brand-black border border-brand-border text-white text-xs font-mono placeholder:text-zinc-600 focus:outline-none focus:border-zinc-400"
                disabled={resendLoading}
                required
              />
              <button
                type="submit"
                disabled={resendLoading}
                className="h-9 px-3.5 text-xs font-medium bg-zinc-800 text-zinc-200 border border-brand-border rounded hover:bg-zinc-700 hover:text-white transition-colors disabled:opacity-50 shrink-0"
              >
                {resendLoading ? "Sending…" : hasSentToken ? "Resend" : "Send"}
              </button>
              {initialEmail && (
                <button
                  type="button"
                  onClick={() => {
                    setEmail(initialEmail);
                    setCustomEmailMode(false);
                  }}
                  className="h-9 px-2 text-xs text-brand-muted hover:text-white font-mono"
                  title="Cancel edit"
                >
                  ✕
                </button>
              )}
            </form>
          )}
        </div>

        <div className="mt-6 pt-4 border-t border-brand-border/60 text-center text-xs text-brand-muted space-x-2">
          <Link to="/" className="text-white hover:underline font-medium">
            Dashboard
          </Link>
          <span>·</span>
          <Link to="/login" className="text-white hover:underline font-medium">
            Sign In
          </Link>
        </div>
      </div>
    </div>
  );
}
