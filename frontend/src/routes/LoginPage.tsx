import { useState, type FormEvent } from "react";
import { useAuth } from "../lib/auth";
import { mn } from "../i18n/mn";

export function LoginPage() {
  const { login } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setError("");
    const result = await login(username, password);
    setSubmitting(false);
    if (!result.success) {
      setError(result.message);
    }
  }

  return (
    <div className="min-h-screen bg-bg flex items-center justify-center px-4">
      <form
        onSubmit={handleSubmit}
        className="w-full max-w-sm rounded-lg border border-border bg-surface p-6 shadow-sm"
      >
        <h1 className="text-lg font-semibold text-text mb-4">{mn.loginTitle}</h1>

        {error && (
          <p className="mb-3 rounded bg-danger-light border border-danger-border px-3 py-2 text-sm text-danger">
            {error}
          </p>
        )}

        <label className="block text-sm text-text-secondary mb-1" htmlFor="username">
          {mn.username}
        </label>
        <input
          id="username"
          className="w-full mb-3 rounded border border-border px-3 py-2 text-sm"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          autoFocus
        />

        <label className="block text-sm text-text-secondary mb-1" htmlFor="password">
          {mn.password}
        </label>
        <input
          id="password"
          type="password"
          className="w-full mb-4 rounded border border-border px-3 py-2 text-sm"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />

        <button
          type="submit"
          disabled={submitting}
          className="w-full rounded bg-primary text-white py-2 text-sm font-medium hover:bg-primary-hover disabled:opacity-60"
        >
          {submitting ? mn.loggingIn : mn.loginButton}
        </button>
      </form>
    </div>
  );
}
