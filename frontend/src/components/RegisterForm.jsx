import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { registerUser, setAuth } from "../api/apiClient.js";

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export default function RegisterForm() {
  const [form, setForm] = useState({ username: "", email: "", password: "" });
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [loading, setLoading] = useState(false);
  const [fieldErrors, setFieldErrors] = useState({});
  const navigate = useNavigate();

  const validateField = (name, value) => {
    let fieldError = "";
    switch (name) {
      case "username":
        if (!value) fieldError = "Username is required";
        else if (value.length < 3) fieldError = "Username must be at least 3 characters";
        else if (value.length > 30) fieldError = "Username must be 30 characters or less";
        else if (!/^[a-zA-Z0-9_-]+$/.test(value)) fieldError = "Only letters, numbers, _ and - allowed";
        break;
      case "email":
        if (!value) fieldError = "Email is required";
        else if (!EMAIL_REGEX.test(value)) fieldError = "Enter a valid email address";
        break;
      case "password":
        if (!value) fieldError = "Password is required";
        else if (value.length < 6) fieldError = "Password must be at least 6 characters";
        break;
    }
    return fieldError;
  };

  const onChange = (e) => {
    const { name, value } = e.target;
    setForm((prev) => ({ ...prev, [name]: value }));
    const fieldError = validateField(name, value);
    setFieldErrors((prev) => ({ ...prev, [name]: fieldError }));
    if (error) setError("");
    if (success) setSuccess("");
  };

  const onBlur = (e) => {
    const { name, value } = e.target;
    const fieldError = validateField(name, value);
    setFieldErrors((prev) => ({ ...prev, [name]: fieldError }));
  };

  const onSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    const usernameError = validateField("username", form.username);
    const emailError = validateField("email", form.email);
    const passwordError = validateField("password", form.password);

    if (usernameError || emailError || passwordError) {
      setFieldErrors({
        username: usernameError,
        email: emailError,
        password: passwordError,
      });
      return;
    }

    setLoading(true);
    try {
      const res = await registerUser(form);
      setSuccess("Account created! A verification token has been sent to your email.");
      setAuth({
        token: res.token,
        userId: res.userId,
        username: res.username,
        email: res.email,
        isVerified: res.isVerified ?? false,
      });
      setTimeout(
        () => navigate("/verify-email", { state: { email: res.email, tokenSent: true } }),
        1200
      );
    } catch (err) {
      const msg = err.message || "Registration failed";
      if (msg.toLowerCase().includes("email") && msg.toLowerCase().includes("exist")) {
        setFieldErrors({ email: "This email is already registered" });
      } else if (msg.toLowerCase().includes("username") && msg.toLowerCase().includes("exist")) {
        setFieldErrors({ username: "This username is already taken" });
      } else {
        setError(msg);
      }
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

      {success && (
        <div className="mb-4 p-3 rounded bg-zinc-900 border border-zinc-700 text-xs text-white font-mono flex items-center gap-2">
          <span>✓</span>
          <span>{success}</span>
        </div>
      )}

      <form onSubmit={onSubmit} className="space-y-4">
        <div>
          <label className="block text-xs font-mono font-medium text-zinc-300 uppercase tracking-wider mb-2" htmlFor="username">
            Username
          </label>
          <input
            id="username"
            name="username"
            className={`w-full h-10 px-3.5 rounded bg-brand-black border ${
              fieldErrors.username ? "border-red-500" : "border-brand-border"
            } text-white text-xs font-mono placeholder:text-zinc-600 focus:outline-none focus:border-zinc-400 transition-colors`}
            placeholder="e.g. sec_lead"
            value={form.username}
            onChange={onChange}
            onBlur={onBlur}
            required
            autoComplete="username"
            minLength={3}
            maxLength={30}
            pattern="[a-zA-Z0-9_-]+"
            aria-invalid={!!fieldErrors.username}
            aria-describedby={fieldErrors.username ? "username-error" : undefined}
          />
          {fieldErrors.username && (
            <p className="mt-1 text-[11px] font-mono text-red-400 flex items-center gap-1" id="username-error" role="alert">
              <span aria-hidden="true">✕</span>
              {fieldErrors.username}
            </p>
          )}
        </div>

        <div>
          <label className="block text-xs font-mono font-medium text-zinc-300 uppercase tracking-wider mb-2" htmlFor="email">
            Email
          </label>
          <input
            id="email"
            name="email"
            type="email"
            className={`w-full h-10 px-3.5 rounded bg-brand-black border ${
              fieldErrors.email ? "border-red-500" : "border-brand-border"
            } text-white text-xs font-mono placeholder:text-zinc-600 focus:outline-none focus:border-zinc-400 transition-colors`}
            placeholder="hello@gmail.com"
            value={form.email}
            onChange={onChange}
            onBlur={onBlur}
            required
            autoComplete="email"
            aria-invalid={!!fieldErrors.email}
            aria-describedby={fieldErrors.email ? "email-error" : undefined}
          />
          {fieldErrors.email && (
            <p className="mt-1 text-[11px] font-mono text-red-400 flex items-center gap-1" id="email-error" role="alert">
              <span aria-hidden="true">✕</span>
              {fieldErrors.email}
            </p>
          )}
        </div>

        <div>
          <label className="block text-xs font-mono font-medium text-zinc-300 uppercase tracking-wider mb-2" htmlFor="password">
            Password (min 6 chars)
          </label>
          <input
            id="password"
            name="password"
            type="password"
            className={`w-full h-10 px-3.5 rounded bg-brand-black border ${
              fieldErrors.password ? "border-red-500" : "border-brand-border"
            } text-white text-xs font-mono placeholder:text-zinc-600 focus:outline-none focus:border-zinc-400 transition-colors`}
            placeholder="••••••••••••"
            value={form.password}
            onChange={onChange}
            onBlur={onBlur}
            required
            minLength={6}
            autoComplete="new-password"
            aria-invalid={!!fieldErrors.password}
            aria-describedby={fieldErrors.password ? "password-error" : undefined}
          />
          {fieldErrors.password && (
            <p className="mt-1 text-[11px] font-mono text-red-400 flex items-center gap-1" id="password-error" role="alert">
              <span aria-hidden="true">✕</span>
              {fieldErrors.password}
            </p>
          )}
        </div>

        <button
          type="submit"
          disabled={loading}
          className="w-full h-10 inline-flex items-center justify-center px-4 text-xs font-medium text-black bg-white rounded border border-white hover:bg-zinc-200 transition-colors disabled:opacity-50 mt-2"
        >
          {loading ? "Creating account…" : "Create Account"}
        </button>
      </form>

      <p className="mt-6 pt-4 border-t border-brand-border/60 text-center text-xs text-brand-muted">
        Already have an account?{" "}
        <Link to="/login" className="text-white hover:underline font-medium">
          Sign in here
        </Link>
      </p>
    </>
  );
}
