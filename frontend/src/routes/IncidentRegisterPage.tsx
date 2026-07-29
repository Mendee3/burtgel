import { useMemo, useState } from "react";
import { useMutation, useQuery } from "@apollo/client/react";
import { DELETE_INCIDENT, GET_INCIDENTS } from "../graphql/operations/incidents";
import { mn } from "../i18n/mn";
import { EMPTY_INCIDENT_FILTERS, filterIncidents, type IncidentFilterValues } from "../lib/incidentFilters";
import { IncidentCard, type Incident } from "./IncidentCard";
import { IncidentFilters } from "./IncidentFilters";
import { IncidentForm } from "./IncidentForm";

type QueryResult = {
  incidents: { totalCount: number; items: Incident[] };
};

export function IncidentRegisterPage() {
  const [createFormOpen, setCreateFormOpen] = useState(false);
  const [draftFilters, setDraftFilters] = useState<IncidentFilterValues>(EMPTY_INCIDENT_FILTERS);
  const [appliedFilters, setAppliedFilters] = useState<IncidentFilterValues>(EMPTY_INCIDENT_FILTERS);

  const { data, loading, error, refetch } = useQuery<QueryResult>(GET_INCIDENTS);
  const [deleteIncident] = useMutation(DELETE_INCIDENT);

  const filteredItems = useMemo(
    () => (data ? filterIncidents(data.incidents.items, appliedFilters) : []),
    [data, appliedFilters],
  );

  async function handleDelete(incident: Incident) {
    if (!window.confirm(mn.incidentDeleteConfirm)) return;
    await deleteIncident({ variables: { id: incident.id } });
    await refetch();
  }

  function handleApplyFilters() {
    setAppliedFilters(draftFilters);
  }

  function handleClearFilters() {
    setDraftFilters(EMPTY_INCIDENT_FILTERS);
    setAppliedFilters(EMPTY_INCIDENT_FILTERS);
  }

  return (
    <div className="px-4 sm:px-6 lg:px-10 py-4 sm:py-6 w-full">
      <h1 className="text-lg font-semibold text-text mb-4">{mn.incidentRegisterTitle}</h1>

      {loading && <p className="text-sm text-muted">{mn.loading}</p>}
      {error && (
        <p className="text-sm text-danger">
          {mn.error}: {error.message}
        </p>
      )}

      {data && (
        <>
          {createFormOpen && (
            <IncidentForm
              incident={null}
              onSaved={() => {
                setCreateFormOpen(false);
                void refetch();
              }}
              onCancel={() => setCreateFormOpen(false)}
            />
          )}

          {!createFormOpen && (
            <IncidentFilters
              draft={draftFilters}
              onChange={setDraftFilters}
              onApply={handleApplyFilters}
              onClear={handleClearFilters}
            />
          )}

          {!createFormOpen && (
            <div className="flex items-center justify-between mb-4">
              <p className="text-sm text-muted">
                {mn.total}: {filteredItems.length}
              </p>
              <button
                onClick={() => setCreateFormOpen(true)}
                className="rounded bg-primary text-white px-3 py-1.5 text-sm font-medium hover:bg-primary-hover"
              >
                + {mn.newIncident}
              </button>
            </div>
          )}

          {!createFormOpen &&
            (filteredItems.length === 0 ? (
              <p className="text-sm text-muted text-center py-6">
                {data.incidents.items.length === 0 ? mn.incidentEmpty : mn.filterNoResults}
              </p>
            ) : (
              <div className="space-y-4">
                {filteredItems.map((incident) => (
                  <IncidentCard
                    key={incident.id}
                    incident={incident}
                    onDelete={handleDelete}
                    onChanged={() => void refetch()}
                  />
                ))}
              </div>
            ))}
        </>
      )}
    </div>
  );
}
