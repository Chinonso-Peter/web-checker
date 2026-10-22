import RegisterForm from "../components/RegisterForm.jsx";

export default function RegisterPage() {
  return (
    <div className="flex-1 flex items-center justify-center py-10">
      <div className="w-full max-w-sm p-6 sm:p-8 rounded-lg border border-brand-border bg-brand-surface">
        <div className="mb-6">
          <span className="text-[11px] font-mono tracking-wider uppercase text-brand-muted block mb-1">Access Registration</span>
          <h1 className="text-xl font-semibold tracking-tight text-white">Create Account</h1>
          <p className="text-xs text-brand-muted mt-1">Get access to automated security scans &amp; audit history</p>
        </div>
        <RegisterForm />
      </div>
    </div>
  );
}
