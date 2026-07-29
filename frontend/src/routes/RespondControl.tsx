import { useState, type FormEvent } from "react";
import { useMutation } from "@apollo/client/react";
import { mn } from "../i18n/mn";
import { ADD_CORRECTIVE_ACTION } from "../graphql/operations/incidents";

type MutationData = {
  addCorrectiveAction?: { __typename: string; message?: string };
};

export function RespondControl({
  incidentId,
  status,
  autoClosedNoResponse,
  onChanged,
}: {
  incidentId: string;
  status: string;
  autoClosedNoResponse: boolean;
  onChanged: () => void;
}) {
  const [formOpen, setFormOpen] = useState(false);
  const [text, setText] = useState("");
  const [error, setError] = useState("");

  const [addCorrectiveAction, { loading }] = useMutation<MutationData>(ADD_CORRECTIVE_ACTION);

  if (status !== "Нээлттэй") {
    if (autoClosedNoResponse) {
      return (
        <span className="text-xs text-danger" onClick={(e) => e.stopPropagation()}>
          {mn.incidentNotRespondedInTime}
        </span>
      );
    }
    return null;
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!text.trim()) return;
    setError("");
    const { data } = await addCorrectiveAction({
      variables: { incidentId, description: text },
    });
    if (data?.addCorrectiveAction?.__typename === "ValidationError") {
      setError(data.addCorrectiveAction.message ?? mn.error);
      return;
    }
    setFormOpen(false);
    setText("");
    onChanged();
  }

  return (
    <div
      className="flex flex-col items-end gap-2"
      onClick={(e) => e.stopPropagation()}
      onKeyDown={(e) => e.stopPropagation()}
    >
      {!formOpen ? (
        <button
          type="button"
          onClick={() => setFormOpen(true)}
          className="rounded-full bg-primary text-white px-3 py-1 text-xs font-medium hover:bg-primary-hover"
        >
          {mn.incidentRespondButton}
        </button>
      ) : (
        <form
          onSubmit={handleSubmit}
          className="w-64 sm:w-72 rounded border border-border bg-surface p-3 space-y-2 shadow-md"
        >
          {error && <p className="text-xs text-danger">{error}</p>}
          <textarea
            autoFocus
            className="w-full rounded border border-border px-2 py-1.5 text-xs"
            placeholder={mn.incidentCorrectiveActionPlaceholder}
            value={text}
            onChange={(e) => setText(e.target.value)}
            rows={2}
          />
          <div className="flex gap-2">
            <button
              type="submit"
              disabled={loading || !text.trim()}
              className="rounded bg-primary text-white px-3 py-1 text-xs font-medium hover:bg-primary-hover disabled:opacity-60"
            >
              {mn.incidentAddCorrectiveAction}
            </button>
            <button
              type="button"
              onClick={() => {
                setFormOpen(false);
                setText("");
                setError("");
              }}
              className="rounded border border-border px-3 py-1 text-xs text-text-secondary hover:bg-surface-alt"
            >
              {mn.cancel}
            </button>
          </div>
        </form>
      )}
    </div>
  );
}
