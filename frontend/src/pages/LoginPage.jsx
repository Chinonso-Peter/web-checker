import LoginForm from "../components/LoginForm.jsx";

export default function LoginPage() {
  return (
    <div className="flex-1 flex items-center justify-center py-10">
      <div className="w-full max-w-sm p-6 sm:p-8 rounded-lg border border-brand-border bg-brand-surface">
        <div className="mb-6">
          <span className="text-[11px] font-mono tracking-wider uppercase text-brand-muted block mb-1">Authentication</span>
          <h1 className="text-xl font-semibold tracking-tight text-white">Welcome Back</h1>
          <p className="text-xs text-brand-muted mt-1">Sign in to your security console to run scans</p>
        </div>
        <LoginForm />
      </div>
    </div>
  );
}
