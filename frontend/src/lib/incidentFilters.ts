import type { Incident } from "../routes/IncidentCard";

export type IncidentFilterValues = {
  search: string;
  severity: string;
  status: string;
};

export const EMPTY_INCIDENT_FILTERS: IncidentFilterValues = {
  search: "",
  severity: "",
  status: "",
};

export function filterIncidents(items: Incident[], filters: IncidentFilterValues): Incident[] {
  const search = filters.search.trim().toLowerCase();

  return items.filter((incident) => {
    if (search) {
      const haystack = `${incident.incidentId} ${incident.incidentType}`.toLowerCase();
      if (!haystack.includes(search)) return false;
    }
    if (filters.severity && incident.severity !== filters.severity) return false;
    if (filters.status === "open" && incident.status !== "Нээлттэй") return false;
    if (filters.status === "action_taken" && incident.status !== "Хариу арга хэмжээ авсан") return false;
    if (filters.status === "closed" && incident.status !== "Хаагдсан") return false;
    return true;
  });
}

export function hasActiveFilters(filters: IncidentFilterValues): boolean {
  return Object.values(filters).some((v) => v !== "");
}
