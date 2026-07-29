import { useState, type FormEvent } from "react";
import { useMutation } from "@apollo/client/react";
import { CHANGE_PASSWORD } from "../graphql/operations/auth";
import { mn } from "../i18n/mn";

type ChangePasswordData = {
  changePassword: { success: boolean; message: string };
};

export function ChangePasswordPage({ onDone }: { onDone: () => void }) {
  const [changePassword] = useMutation<ChangePasswordData>(CHANGE_PASSWORD);
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [message, setMessage] = useState("");
  const [isError, setIsError] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    const { data } = await changePassword({ variables: { currentPassword, newPassword } });
    setSubmitting(false);
    const outcome = data?.changePassword;
    if (outcome?.success) {
      setIsError(false);
      setMessage(mn.changePasswordSuccess);
      setTimeout(onDone, 800);
    } else {
      setIsError(true);
      setMessage(outcome?.message ?? mn.error);
    }
  }

  return (
    <div className="min-h-screen bg-bg flex items-center justify-center px-4">
      <form
        onSubmit={handleSubmit}
        className="w-full max-w-sm rounded-lg border border-border bg-surface p-6 shadow-sm"
      >
        <h1 className="text-lg font-semibold text-text mb-1">{mn.mustChangePasswordTitle}</h1>
        <p className="text-sm text-muted mb-4">{mn.mustChangePasswordBody}</p>

        {message && (
          <p
            className={`mb-3 rounded border px-3 py-2 text-sm ${
              isError ? "bg-danger-light border-danger-border text-danger" : "bg-success-light border-success text-success"
            }`}
          >
            {message}
          </p>
        )}

        <label className="block text-sm text-text-secondary mb-1" htmlFor="current-password">
          {mn.currentPassword}
        </label>
        <input
          id="current-password"
          type="password"
          className="w-full mb-3 rounded border border-border px-3 py-2 text-sm"
          value={currentPassword}
          onChange={(e) => setCurrentPassword(e.target.value)}
        />

        <label className="block text-sm text-text-secondary mb-1" htmlFor="new-password">
          {mn.newPassword}
        </label>
        <input
          id="new-password"
          type="password"
          className="w-full mb-4 rounded border border-border px-3 py-2 text-sm"
          value={newPassword}
          onChange={(e) => setNewPassword(e.target.value)}
        />

        <button
          type="submit"
          disabled={submitting}
          className="w-full rounded bg-primary text-white py-2 text-sm font-medium hover:bg-primary-hover disabled:opacity-60"
        >
          {submitting ? mn.changingPassword : mn.changePasswordButton}
        </button>
      </form>
    </div>
  );
}
