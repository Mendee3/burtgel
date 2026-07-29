import { useState, type FormEvent } from "react";
import { useMutation } from "@apollo/client/react";
import { CREATE_INCIDENT, UPDATE_INCIDENT } from "../graphql/operations/incidents";
import { INCIDENT_FIELDS, resolutionTimeForSeverity } from "../lib/incidentFields";
import { mn } from "../i18n/mn";

type Incident = { id: string; incidentId: string; [key: string]: unknown };

type IncidentInputVars = Record<string, string>;

type MutationData = {
  createIncident?: { __typename: string; message?: string } & Partial<Incident>;
  updateIncident?: { __typename: string; message?: string } & Partial<Incident>;
};

export function IncidentForm({
  incident,
  onSaved,
  onCancel,
}: {
  incident: Incident | null;
  onSaved: () => void;
  onCancel: () => void;
}) {
  const isEdit = !!incident;
  const [values, setValues] = useState<IncidentInputVars>(() => {
    const initial: IncidentInputVars = {};
    for (const field of INCIDENT_FIELDS) {
      initial[field.key] = (incident?.[field.key] as string) ?? (field.options ? "" : "");
    }
    return initial;
  });
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const [createIncident] = useMutation<MutationData>(CREATE_INCIDENT);
  const [updateIncident] = useMutation<MutationData>(UPDATE_INCIDENT);

  function setField(key: string, value: string) {
    setValues((prev) => {
      const next = { ...prev, [key]: value };
      if (key === "severity" && !isEdit) {
        next.resolutionTime = resolutionTimeForSeverity(value);
      }
      return next;
    });
  }

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setError("");

    const result = isEdit
      ? await updateIncident({ variables: { id: incident!.id, input: values } })
      : await createIncident({ variables: { input: values } });

    setSubmitting(false);
    const outcome = isEdit ? result.data?.updateIncident : result.data?.createIncident;
    if (outcome?.__typename === "ValidationError") {
      setError(outcome.message ?? mn.error);
      return;
    }
    onSaved();
  }

  return (
    <form
      onSubmit={handleSubmit}
      className="rounded-lg border border-border bg-surface p-5 mb-4 grid grid-cols-1 sm:grid-cols-2 gap-4"
    >
      <div className="col-span-full flex items-center gap-2">
        <button
          type="button"
          onClick={onCancel}
          title={mn.back}
          aria-label={mn.back}
          className="flex items-center justify-center rounded p-1.5 text-text-secondary hover:bg-surface-alt hover:text-text"
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <path d="M19 12H5" />
            <path d="M12 19l-7-7 7-7" />
          </svg>
        </button>
        <h2 className="text-base font-semibold text-text">
          {isEdit ? `${mn.editIncident} — ${incident!.incidentId}` : mn.newIncident}
        </h2>
      </div>

      {error && (
        <p className="col-span-full rounded bg-danger-light border border-danger-border px-3 py-2 text-sm text-danger">
          {error}
        </p>
      )}

      {INCIDENT_FIELDS.map((field) => {
        const wide = field.kind === "textarea";
        return (
          <div key={field.key} className={wide ? "col-span-full" : ""}>
            <label className="block text-sm font-medium text-text-secondary mb-1">
              {field.label}
              {field.required && <span className="text-danger"> *</span>}
            </label>
            {field.kind === "select" ? (
              <select
                className="w-full rounded border border-border px-3 py-2 text-sm"
                value={values[field.key]}
                onChange={(e) => setField(field.key, e.target.value)}
              >
                <option value="">— сонгох —</option>
                {field.options!.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            ) : field.kind === "textarea" ? (
              <textarea
                className="w-full rounded border border-border px-3 py-2 text-sm"
                rows={3}
                value={values[field.key]}
                onChange={(e) => setField(field.key, e.target.value)}
              />
            ) : field.kind === "date" ? (
              <input
                type="date"
                className="w-full rounded border border-border px-3 py-2 text-sm"
                value={values[field.key]}
                onChange={(e) => setField(field.key, e.target.value)}
              />
            ) : (
              <input
                className="w-full rounded border border-border px-3 py-2 text-sm"
                value={values[field.key]}
                onChange={(e) => setField(field.key, e.target.value)}
              />
            )}
          </div>
        );
      })}

      <div className="col-span-full flex gap-2 pt-2">
        <button
          type="submit"
          disabled={submitting}
          className="rounded bg-primary text-white px-4 py-2 text-sm font-medium hover:bg-primary-hover disabled:opacity-60"
        >
          {submitting ? mn.saving : mn.save}
        </button>
        <button
          type="button"
          onClick={onCancel}
          className="rounded border border-border px-4 py-2 text-sm text-text-secondary hover:bg-surface-alt"
        >
          {mn.cancel}
        </button>
      </div>
    </form>
  );
}
