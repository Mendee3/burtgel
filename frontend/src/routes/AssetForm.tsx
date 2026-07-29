import { useState, type FormEvent } from "react";
import { useMutation } from "@apollo/client/react";
import { CREATE_ASSET, UPDATE_ASSET } from "../graphql/operations/assets";
import { ASSET_FIELDS, FIELD_KEY_TO_GRAPHQL } from "../lib/assetFields";
import { mn } from "../i18n/mn";

type Asset = Record<string, string> & { id: string };

type AssetInputVars = Record<string, string>;

type MutationData = {
  createAsset?: { __typename: string; message?: string } & Partial<Asset>;
  updateAsset?: { __typename: string; message?: string } & Partial<Asset>;
};

export function AssetForm({
  departmentSlug,
  editableFields,
  asset,
  onSaved,
  onCancel,
}: {
  departmentSlug: string;
  editableFields: string[];
  asset: Asset | null;
  onSaved: () => void;
  onCancel: () => void;
}) {
  const isEdit = !!asset;
  const editableSet = new Set(editableFields);
  const [values, setValues] = useState<AssetInputVars>(() => {
    const initial: AssetInputVars = {};
    for (const field of ASSET_FIELDS) {
      initial[field.key] = (asset?.[field.key] as string) ?? (field.options ? field.options[0]?.value ?? "" : "");
    }
    return initial;
  });
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const [createAsset] = useMutation<MutationData>(CREATE_ASSET);
  const [updateAsset] = useMutation<MutationData>(UPDATE_ASSET);

  function setField(key: string, value: string) {
    setValues((prev) => ({ ...prev, [key]: value }));
  }

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setError("");

    const variables = { departmentSlug, input: values };
    const result = isEdit
      ? await updateAsset({ variables: { ...variables, id: asset!.id } })
      : await createAsset({ variables });

    setSubmitting(false);
    const outcome = isEdit ? result.data?.updateAsset : result.data?.createAsset;
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
        <h2 className="text-base font-semibold text-text">{isEdit ? mn.editAsset : mn.newAsset}</h2>
      </div>

      {error && (
        <p className="col-span-full rounded bg-danger-light border border-danger-border px-3 py-2 text-sm text-danger">
          {error}
        </p>
      )}

      {ASSET_FIELDS.map((field) => {
        const graphqlKey = FIELD_KEY_TO_GRAPHQL[field.key];
        const editable = editableSet.has(graphqlKey);
        const wide = field.kind === "textarea";
        return (
          <div key={field.key} className={wide ? "col-span-full" : ""}>
            <label className="block text-sm text-text-secondary mb-1">
              {field.label}
              {field.required && editable && <span className="text-danger"> *</span>}
              {!editable && <span className="text-muted text-xs"> ({mn.locked})</span>}
            </label>
            {field.kind === "select" ? (
              <select
                className="w-full rounded border border-border px-3 py-2 text-sm disabled:bg-surface-alt disabled:text-muted"
                value={values[field.key]}
                disabled={!editable}
                onChange={(e) => setField(field.key, e.target.value)}
              >
                {field.options!.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            ) : field.kind === "textarea" ? (
              <textarea
                className="w-full rounded border border-border px-3 py-2 text-sm disabled:bg-surface-alt disabled:text-muted"
                rows={2}
                value={values[field.key]}
                disabled={!editable}
                onChange={(e) => setField(field.key, e.target.value)}
              />
            ) : (
              <input
                className="w-full rounded border border-border px-3 py-2 text-sm disabled:bg-surface-alt disabled:text-muted"
                value={values[field.key]}
                disabled={!editable}
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
