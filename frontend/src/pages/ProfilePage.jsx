import { useState, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import { getAuth, setAuth, clearAuth, updateUser, fetchCurrentUser, deleteAccount } from "../api/apiClient.js";

export default function ProfilePage() {
  const navigate = useNavigate();
  const [form, setForm] = useState({
    username: "",
    email: "",
    currentPassword: "",
    newPassword: "",
    confirmPassword: "",
  });
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState("profile");
  const auth = getAuth();
  const [isVerified, setIsVerified] = useState(auth?.isVerified ?? false);

  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [deletePassword, setDeletePassword] = useState("");
  const [deleteLoading, setDeleteLoading] = useState(false);
  const [deleteError, setDeleteError] = useState("");

  useEffect(() => {
    if (auth) {
      setForm((prev) => ({ ...prev, username: auth.username || "", email: auth.email || "" }));
      fetchCurrentUser()
        .then((userData) => {
          if (userData) {
            setIsVerified(Boolean(userData.isVerified));
            setAuth({ ...auth, isVerified: Boolean(userData.isVerified), email: userData.email, username: userData.username });
          }
        })
        .catch(() => {});
    }
  }, []);

  const onChange = (e) => {
    const { name, value } = e.target;
    setForm((prev) => ({ ...prev, [name]: value }));
    if (error) setError("");
    if (success) setSuccess("");
  };

  const handleProfileUpdate = async (e) => {
    e.preventDefault();
    setError("");
    setSuccess("");
    setLoading(true);

    try {
      const payload = {
        username: form.username,
        email: form.email,
      };
      if (form.currentPassword) {
        if (form.newPassword && form.newPassword !== form.confirmPassword) {
          throw new Error("New passwords do not match");
        }
        payload.currentPassword = form.currentPassword;
        payload.newPassword = form.newPassword;
      }

      const res = await updateUser(payload);
      setAuth({ ...auth, username: res.username, email: res.email });
      setForm((prev) => ({ ...prev, currentPassword: "", newPassword: "", confirmPassword: "" }));
      setSuccess("Profile settings updated successfully");
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteAccount = async (e) => {
    e.preventDefault();
    setDeleteError("");
    if (!deletePassword) {
      setDeleteError("Password is required to confirm account deletion.");
      return;
    }

    setDeleteLoading(true);
    try {
      await deleteAccount(deletePassword);
      clearAuth();
      setShowDeleteModal(false);
      navigate("/register");
    } catch (err) {
      setDeleteError(err.message || "Failed to delete account.");
    } finally {
      setDeleteLoading(false);
    }
  };

  const initial = form.username ? form.username.charAt(0).toUpperCase() : "U";

  return (
    <div className="flex flex-col">
      <div className="mb-8 pb-4 border-b border-brand-border flex items-baseline justify-between">
        <div>
          <h1 className="text-xl sm:text-2xl font-semibold tracking-tight text-white">
            Security Profile &amp; Settings
          </h1>
          <p className="text-xs text-brand-muted mt-1">Manage operator credentials and account configuration</p>
        </div>
        <span className="text-[11px] font-mono text-zinc-500 uppercase tracking-wider">
          User Settings
        </span>
      </div>

      <div className="max-w-2xl rounded-lg border border-brand-border bg-brand-surface overflow-hidden">
        {/* User Identity Banner */}
        <div className="flex items-center gap-4 p-6 border-b border-brand-border bg-brand-subtle">
          <div className="w-12 h-12 rounded bg-zinc-800 text-white font-semibold text-lg flex items-center justify-center border border-brand-border">
            {initial}
          </div>
          <div>
            <h2 className="text-sm font-semibold text-white">{form.username || "Operator"}</h2>
            <p className="text-xs font-mono text-zinc-500 mt-0.5 flex items-center gap-2">
              <span>{form.email || "No email"}</span>
              <span>·</span>
              <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] uppercase font-bold tracking-wider ${
                isVerified ? "bg-teal-500/20 text-teal-300 border border-teal-500/30" : "bg-amber-500/20 text-amber-300 border border-amber-500/30"
              }`}>
                {isVerified ? "✓ Verified" : "Unverified"}
              </span>
            </p>
          </div>
        </div>

        <div className="p-6">
          {/* Tabs */}
          <div className="flex gap-2 border-b border-brand-border mb-6">
            <button
              type="button"
              className={`px-3 py-2 text-xs font-medium font-mono border-b-2 transition-colors ${
                activeTab === "profile"
                  ? "border-white text-white"
                  : "border-transparent text-brand-muted hover:text-white"
              }`}
              onClick={() => setActiveTab("profile")}
            >
              Account Details
            </button>
            <button
              type="button"
              className={`px-3 py-2 text-xs font-medium font-mono border-b-2 transition-colors ${
                activeTab === "security"
                  ? "border-white text-white"
                  : "border-transparent text-brand-muted hover:text-white"
              }`}
              onClick={() => setActiveTab("security")}
            >
              Password &amp; Security
            </button>
          </div>

          <form onSubmit={handleProfileUpdate} className="space-y-4">
            {activeTab === "profile" && (
              <>
                <div>
                  <label className="block text-xs font-mono font-medium text-zinc-300 uppercase tracking-wider mb-2" htmlFor="username">
                    Username
                  </label>
                  <input
                    id="username"
                    name="username"
                    className="w-full h-10 px-3.5 rounded bg-brand-black border border-brand-border text-white text-xs font-mono placeholder:text-zinc-600 focus:outline-none focus:border-zinc-400 transition-colors"
                    value={form.username}
                    onChange={onChange}
                    required
                    autoComplete="username"
                    minLength={3}
                    maxLength={30}
                  />
                </div>

                <div>
                  <label className="block text-xs font-mono font-medium text-zinc-300 uppercase tracking-wider mb-2" htmlFor="email">
                    Email Address
                  </label>
                  <input
                    id="email"
                    name="email"
                    type="email"
                    className="w-full h-10 px-3.5 rounded bg-brand-black border border-brand-border text-white text-xs font-mono placeholder:text-zinc-600 focus:outline-none focus:border-zinc-400 transition-colors"
                    value={form.email}
                    onChange={onChange}
                    required
                    autoComplete="email"
                  />
                  {isVerified ? (
                    <span className="text-[11px] text-teal-400 font-mono mt-1.5 flex items-center gap-1.5">
                      <span>✓</span> Email address is verified
                    </span>
                  ) : (
                    <div className="flex items-center justify-between mt-1.5">
                      <span className="text-[11px] text-amber-400 font-mono flex items-center gap-1.5">
                        <span>⚠</span> Email address is unverified
                      </span>
                      <Link to="/verify-email" className="text-[11px] font-mono text-teal-400 hover:underline">
                        Verify now →
                      </Link>
                    </div>
                  )}
                </div>
              </>
            )}

            {activeTab === "security" && (
              <>
                <p className="text-xs text-brand-muted mb-4 font-mono">
                  Leave password fields empty to keep your current credentials.
                </p>

                <div>
                  <label className="block text-xs font-mono font-medium text-zinc-300 uppercase tracking-wider mb-2" htmlFor="currentPassword">
                    Current Password
                  </label>
                  <input
                    id="currentPassword"
                    name="currentPassword"
                    type="password"
                    className="w-full h-10 px-3.5 rounded bg-brand-black border border-brand-border text-white text-xs font-mono placeholder:text-zinc-600 focus:outline-none focus:border-zinc-400 transition-colors"
                    value={form.currentPassword}
                    onChange={onChange}
                    autoComplete="current-password"
                    placeholder="Enter current password to authorize changes"
                  />
                </div>

                <div>
                  <label className="block text-xs font-mono font-medium text-zinc-300 uppercase tracking-wider mb-2" htmlFor="newPassword">
                    New Password
                  </label>
                  <input
                    id="newPassword"
                    name="newPassword"
                    type="password"
                    className="w-full h-10 px-3.5 rounded bg-brand-black border border-brand-border text-white text-xs font-mono placeholder:text-zinc-600 focus:outline-none focus:border-zinc-400 transition-colors"
                    value={form.newPassword}
                    onChange={onChange}
                    autoComplete="new-password"
                    placeholder="Minimum 6 characters"
                    minLength={6}
                  />
                </div>

                <div>
                  <label className="block text-xs font-mono font-medium text-zinc-300 uppercase tracking-wider mb-2" htmlFor="confirmPassword">
                    Confirm New Password
                  </label>
                  <input
                    id="confirmPassword"
                    name="confirmPassword"
                    type="password"
                    className="w-full h-10 px-3.5 rounded bg-brand-black border border-brand-border text-white text-xs font-mono placeholder:text-zinc-600 focus:outline-none focus:border-zinc-400 transition-colors"
                    value={form.confirmPassword}
                    onChange={onChange}
                    autoComplete="new-password"
                    placeholder="Confirm new password"
                  />
                </div>
              </>
            )}

            {error && (
              <div className="p-3 rounded bg-red-500/10 border border-red-500/30 text-xs text-red-400 font-mono flex items-center gap-2" role="alert">
                <span aria-hidden="true">⚠</span>
                <span>{error}</span>
              </div>
            )}

            {success && (
              <div className="p-3 rounded bg-zinc-900 border border-zinc-700 text-xs text-white font-mono flex items-center gap-2">
                <span>✓</span>
                <span>{success}</span>
              </div>
            )}

            <div className="pt-2">
              <button
                type="submit"
                disabled={loading}
                className="inline-flex items-center justify-center px-5 py-2.5 text-xs font-medium text-black bg-white rounded border border-white hover:bg-zinc-200 transition-colors disabled:opacity-50"
              >
                {loading ? "Saving…" : "Save Changes"}
              </button>
            </div>
          </form>

          {/* Danger Zone */}
          <div className="mt-10 pt-6 border-t border-red-500/20">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <h3 className="text-xs font-semibold text-red-400 uppercase tracking-wider font-mono">
                  Danger Zone
                </h3>
                <p className="text-xs text-brand-muted mt-0.5">
                  Permanently delete your account, saved scans, and vulnerability reports.
                </p>
              </div>
              <button
                type="button"
                onClick={() => {
                  setDeleteError("");
                  setDeletePassword("");
                  setShowDeleteModal(true);
                }}
                className="px-3.5 py-2 text-xs font-medium text-red-400 bg-red-500/10 border border-red-500/30 rounded hover:bg-red-500/20 hover:border-red-500/50 transition-colors self-start sm:self-auto"
              >
                Delete Account
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Delete Account Confirmation Modal */}
      {showDeleteModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="w-full max-w-md p-6 rounded-lg border border-red-500/30 bg-brand-surface shadow-2xl">
            <div className="flex items-center gap-2 mb-2">
              <span className="text-red-400 text-base" aria-hidden="true">⚠</span>
              <h3 className="text-base font-semibold text-white">Delete Account</h3>
            </div>
            <p className="text-xs text-zinc-400 mb-4">
              This action is permanent and cannot be undone. All your account details, active sessions, and scan reports will be permanently deleted.
            </p>

            {deleteError && (
              <div className="mb-4 p-3 rounded bg-red-500/10 border border-red-500/30 text-xs text-red-400 font-mono flex items-center gap-2" role="alert">
                <span aria-hidden="true">⚠</span>
                <span>{deleteError}</span>
              </div>
            )}

            <form onSubmit={handleDeleteAccount} className="space-y-4">
              <div>
                <label className="block text-xs font-mono font-medium text-zinc-300 uppercase tracking-wider mb-2" htmlFor="deletePassword">
                  Enter Password to Confirm
                </label>
                <input
                  id="deletePassword"
                  type="password"
                  value={deletePassword}
                  onChange={(e) => {
                    setDeletePassword(e.target.value);
                    if (deleteError) setDeleteError("");
                  }}
                  className="w-full h-10 px-3.5 rounded bg-brand-black border border-brand-border text-white text-xs font-mono placeholder:text-zinc-600 focus:outline-none focus:border-red-500 transition-colors"
                  placeholder="Your account password"
                  required
                  autoFocus
                  disabled={deleteLoading}
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowDeleteModal(false)}
                  disabled={deleteLoading}
                  className="px-4 py-2 text-xs font-medium text-zinc-300 bg-zinc-800 rounded border border-brand-border hover:bg-zinc-700 transition-colors disabled:opacity-50"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={deleteLoading}
                  className="px-4 py-2 text-xs font-medium text-white bg-red-600 rounded hover:bg-red-700 transition-colors disabled:opacity-50"
                >
                  {deleteLoading ? "Deleting Account…" : "Permanently Delete"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
