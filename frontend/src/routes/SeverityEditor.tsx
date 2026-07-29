import { useState, type FormEvent } from "react";
import { useMutation } from "@apollo/client/react";
import { SeverityBadge } from "../components/SeverityBadge";
import { mn } from "../i18n/mn";
import { CHANGE_INCIDENT_SEVERITY } from "../graphql/operations/incidents";

const SEVERITY_OPTIONS = ["Бага", "Дунд", "Өндөр", "Маш Өндөр"];

type MutationData = {
  changeIncidentSeverity?: { __typename: string; message?: string };
};

export function SeverityEditor({
  incidentId,
  currentSeverity,
  previousSeverity,
  onChanged,
}: {
  incidentId: string;
  currentSeverity: string;
  previousSeverity?: string;
  onChanged: () => void;
}) {
  const [mode, setMode] = useState<"idle" | "selecting" | "confirming">("idle");
  const [pendingSeverity, setPendingSeverity] = useState("");
  const [reason, setReason] = useState("");
  const [error, setError] = useState("");

  const [changeSeverity, { loading }] = useMutation<MutationData>(CHANGE_INCIDENT_SEVERITY);

  function handleSelect(value: string) {
    if (value === currentSeverity) {
      setMode("idle");
      return;
    }
    setPendingSeverity(value);
    setError("");
    setMode("confirming");
  }

  function handleCancel() {
    setMode("idle");
    setPendingSeverity("");
    setReason("");
    setError("");
  }

  async function handleConfirm(e: FormEvent) {
    e.preventDefault();
    if (!reason.trim()) {
      setError(mn.incidentSeverityReasonRequired);
      return;
    }
    setError("");
    const { data } = await changeSeverity({
      variables: { incidentId, newSeverity: pendingSeverity, reason },
    });
    if (data?.changeIncidentSeverity?.__typename === "ValidationError") {
      setError(data.changeIncidentSeverity.message ?? mn.error);
      return;
    }
    setMode("idle");
    setReason("");
    onChanged();
  }

  return (
    <div
      className="flex flex-col items-end gap-2"
      onClick={(e) => e.stopPropagation()}
      onKeyDown={(e) => e.stopPropagation()}
    >
      <div className="flex items-center gap-1.5">
        {previousSeverity && (
          <>
            <SeverityBadge severity={previousSeverity} size="sm" />
            <span className="text-muted text-sm" aria-hidden="true">
              →
            </span>
          </>
        )}
        {mode === "selecting" ? (
          <select
            autoFocus
            className="rounded-full border border-border px-2 py-1 text-xs"
            value={currentSeverity}
            onChange={(e) => handleSelect(e.target.value)}
            onBlur={() => setMode("idle")}
          >
            {SEVERITY_OPTIONS.map((opt) => (
              <option key={opt} value={opt}>
                {opt}
              </option>
            ))}
          </select>
        ) : (
          <button type="button" onClick={() => setMode("selecting")} title={mn.incidentChangeSeverity}>
            <SeverityBadge severity={currentSeverity} />
          </button>
        )}
      </div>

      {mode === "confirming" && (
        <form
          onSubmit={handleConfirm}
          className="w-64 sm:w-72 rounded border border-border bg-surface p-3 space-y-2 shadow-md"
        >
          <p className="text-xs text-text-secondary">
            {mn.incidentSeverityConfirmPrefix} <span className="font-medium text-text">{currentSeverity}</span>{" "}
            {mn.incidentSeverityConfirmArrow}{" "}
            <span className="font-medium text-text">{pendingSeverity}</span>?
          </p>
          {error && <p className="text-xs text-danger">{error}</p>}
          <textarea
            autoFocus
            className="w-full rounded border border-border px-2 py-1.5 text-xs"
            placeholder={mn.incidentSeverityReasonPlaceholder}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            rows={2}
          />
          <div className="flex gap-2">
            <button
              type="submit"
              disabled={loading}
              className="rounded bg-primary text-white px-3 py-1 text-xs font-medium hover:bg-primary-hover disabled:opacity-60"
            >
              {mn.save}
            </button>
            <button
              type="button"
              onClick={handleCancel}
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
