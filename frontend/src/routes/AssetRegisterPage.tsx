import { useEffect, useState } from "react";
import { useMutation, useQuery } from "@apollo/client/react";
import { DELETE_ASSET, GET_DEPARTMENT_ASSETS, GET_DEPARTMENTS } from "../graphql/operations/assets";
import { mn } from "../i18n/mn";
import { useAuth } from "../lib/auth";
import { AssetForm } from "./AssetForm";

const CATEGORY_STYLE: Record<string, string> = {
  CAT1: "bg-danger-light text-danger",
  CAT2: "bg-warning-light text-warning",
  CAT3: "bg-success-light text-success",
};

type Asset = {
  id: string;
  assetName: string;
  description: string;
  assetType: string;
  assetGroupCode: string;
  hasPersonalData: string;
  hasSensitiveData: string;
  owner: string;
  custodian: string;
  location: string;
  retentionPeriod: string;
  confidentiality: string;
  integrityImpact: string;
  availabilityImpact: string;
  assetValue: string;
  assetCategory: string;
};

type Department = { id: string; slug: string; name: string };

type DepartmentsResult = { departments: Department[] };

type AssetsResult = {
  assetPermissions: { canRead: boolean; canUpdate: boolean; editableFields: string[] };
  assets: { totalCount: number; items: Asset[] };
};

export function AssetRegisterPage() {
  const { user } = useAuth();
  const [departmentSlug, setDepartmentSlug] = useState(user?.department?.slug ?? "");
  const [formOpen, setFormOpen] = useState(false);
  const [editingAsset, setEditingAsset] = useState<Asset | null>(null);

  const { data: deptData, loading: deptLoading, error: deptError } = useQuery<DepartmentsResult>(GET_DEPARTMENTS);
  const departments = deptData?.departments ?? [];

  useEffect(() => {
    if (!departmentSlug && departments.length > 0) {
      setDepartmentSlug(departments[0].slug);
    }
  }, [departmentSlug, departments]);

  const activeSlug = departmentSlug || departments[0]?.slug || "";

  const { data, loading, error, refetch } = useQuery<AssetsResult>(GET_DEPARTMENT_ASSETS, {
    variables: { departmentSlug: activeSlug },
    skip: !activeSlug,
  });
  const [deleteAsset] = useMutation(DELETE_ASSET);

  const department = departments.find((d) => d.slug === activeSlug);
  const permissions = data?.assetPermissions;

  function openCreate() {
    setEditingAsset(null);
    setFormOpen(true);
  }

  function openEdit(asset: Asset) {
    setEditingAsset(asset);
    setFormOpen(true);
  }

  async function handleDelete(asset: Asset) {
    if (!window.confirm(mn.deleteConfirm)) return;
    await deleteAsset({ variables: { departmentSlug: activeSlug, id: asset.id } });
    await refetch();
  }

  return (
      <main className="p-6">
        <div className="mb-4">
          <h1 className="text-lg font-semibold text-text">{mn.assetRegisterTitle}</h1>
          {department && <p className="text-sm text-muted mt-1">{department.name}</p>}
        </div>

        {departments.length > 1 && (
          <label className="block mb-4 text-sm">
            <span className="text-text-secondary mr-2">{mn.department}:</span>
            <select
              className="rounded border border-border px-2 py-1"
              value={activeSlug}
              onChange={(e) => {
                setDepartmentSlug(e.target.value);
                setFormOpen(false);
              }}
            >
              {departments.map((d) => (
                <option key={d.slug} value={d.slug}>
                  {d.name}
                </option>
              ))}
            </select>
          </label>
        )}

        {(deptLoading || loading) && <p className="text-sm text-muted">{mn.loading}</p>}
        {(deptError || error) && (
          <p className="text-sm text-danger">
            {mn.error}: {(deptError ?? error)?.message}
          </p>
        )}
        {!deptLoading && departments.length === 0 && <p className="text-sm text-muted">{mn.noDepartments}</p>}

        {data && permissions && (
          <>
            {formOpen && (
              <AssetForm
                departmentSlug={activeSlug}
                editableFields={permissions.editableFields}
                asset={editingAsset}
                onSaved={() => {
                  setFormOpen(false);
                  void refetch();
                }}
                onCancel={() => setFormOpen(false)}
              />
            )}

            <div className="flex items-center justify-between mb-3">
              <p className="text-sm text-muted">
                {mn.total}: {data.assets.totalCount}
              </p>
              {permissions.canUpdate ? (
                !formOpen && (
                  <button
                    onClick={openCreate}
                    className="rounded bg-primary text-white px-3 py-1.5 text-sm font-medium hover:bg-primary-hover"
                  >
                    + {mn.newAsset}
                  </button>
                )
              ) : (
                <span className="text-sm text-muted">{mn.readOnlyNotice}</span>
              )}
            </div>

            <div className="overflow-hidden rounded-lg border border-border bg-surface">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-text-secondary border-b border-border">
                    <th className="px-4 py-2 font-medium">{mn.assetName}</th>
                    <th className="px-4 py-2 font-medium">{mn.owner}</th>
                    <th className="px-4 py-2 font-medium">{mn.location}</th>
                    <th className="px-4 py-2 font-medium">{mn.confidentiality}</th>
                    <th className="px-4 py-2 font-medium">{mn.score}</th>
                    <th className="px-4 py-2 font-medium">{mn.category}</th>
                    {permissions.canUpdate && <th className="px-4 py-2 font-medium"></th>}
                  </tr>
                </thead>
                <tbody>
                  {data.assets.items.length === 0 && (
                    <tr>
                      <td colSpan={7} className="px-4 py-6 text-center text-muted">
                        {mn.empty}
                      </td>
                    </tr>
                  )}
                  {data.assets.items.map((asset) => (
                    <tr key={asset.id} className="border-b border-border last:border-0">
                      <td className="px-4 py-2 font-medium text-text">{asset.assetName}</td>
                      <td className="px-4 py-2 text-text-secondary">{asset.owner}</td>
                      <td className="px-4 py-2 text-text-secondary">{asset.location}</td>
                      <td className="px-4 py-2 text-text-secondary">{asset.confidentiality}</td>
                      <td className="px-4 py-2 text-text-secondary">{asset.assetValue}</td>
                      <td className="px-4 py-2">
                        <span
                          className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${
                            CATEGORY_STYLE[asset.assetCategory] ?? "bg-surface-alt text-muted"
                          }`}
                        >
                          {asset.assetCategory || "—"}
                        </span>
                      </td>
                      {permissions.canUpdate && (
                        <td className="px-4 py-2 text-right whitespace-nowrap">
                          <button onClick={() => openEdit(asset)} className="text-primary hover:underline mr-3">
                            {mn.edit}
                          </button>
                          <button onClick={() => void handleDelete(asset)} className="text-danger hover:underline">
                            {mn.delete}
                          </button>
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </main>
  );
}
