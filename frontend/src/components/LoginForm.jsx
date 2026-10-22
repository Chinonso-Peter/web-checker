import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { loginUser, setAuth } from "../api/apiClient.js";

export default function LoginForm() {
  const [form, setForm] = useState({ username: "", password: "" });
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const onChange = (e) =>
    setForm({ ...form, [e.target.name]: e.target.value });

  const onSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const res = await loginUser(form);
      setAuth({
        token: res.token,
        userId: res.userId,
        username: res.username,
        email: res.email,
        isVerified: res.isVerified ?? false,
      });
      navigate("/scan");
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      {error && (
        <div className="mb-4 p-3 rounded bg-red-500/10 border border-red-500/30 text-xs text-red-400 font-mono flex items-center gap-2" role="alert">
          <span aria-hidden="true">⚠</span>
          <span>{error}</span>
        </div>
      )}

      <form onSubmit={onSubmit} className="space-y-4">
        <div>
          <div className="flex items-center justify-between mb-2">
            <label className="block text-xs font-mono font-medium text-zinc-300 uppercase tracking-wider" htmlFor="username">
              Username or Email
            </label>
            <Link to="/forgot-password?tab=username" className="text-[11px] font-mono text-zinc-500 hover:text-zinc-300 transition-colors">
              Forgot username?
            </Link>
          </div>
          <input
            id="username"
            name="username"
            className="w-full h-10 px-3.5 rounded bg-brand-black border border-brand-border text-white text-xs font-mono placeholder:text-zinc-600 focus:outline-none focus:border-zinc-400 transition-colors"
            placeholder="auditor or hello@gmail.com"
            value={form.username}
            onChange={onChange}
            required
            autoComplete="username"
          />
        </div>

        <div>
          <div className="flex items-center justify-between mb-2">
            <label className="block text-xs font-mono font-medium text-zinc-300 uppercase tracking-wider" htmlFor="password">
              Password
            </label>
            <Link to="/forgot-password" className="text-[11px] font-mono text-zinc-400 hover:text-white transition-colors">
              Forgot password?
            </Link>
          </div>
          <input
            id="password"
            name="password"
            type="password"
            className="w-full h-10 px-3.5 rounded bg-brand-black border border-brand-border text-white text-xs font-mono placeholder:text-zinc-600 focus:outline-none focus:border-zinc-400 transition-colors"
            placeholder="••••••••••••"
            value={form.password}
            onChange={onChange}
            required
            autoComplete="current-password"
          />
        </div>

        <button
          type="submit"
          disabled={loading}
          className="w-full h-10 inline-flex items-center justify-center px-4 text-xs font-medium text-black bg-white rounded border border-white hover:bg-zinc-200 transition-colors disabled:opacity-50 mt-2"
        >
          {loading ? "Signing in…" : "Sign In to Scan"}
        </button>
      </form>

      <p className="mt-6 pt-4 border-t border-brand-border/60 text-center text-xs text-brand-muted">
        Need an account?{" "}
        <Link to="/register" className="text-white hover:underline font-medium">
          Create one now
        </Link>
      </p>
    </>
  );
}
