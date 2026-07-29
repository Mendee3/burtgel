import { gql } from "@apollo/client";

export const INCIDENT_FIELDS_FRAGMENT = gql`
  fragment IncidentFields on IncidentType {
    id
    incidentId
    detectedDate
    occurredDate
    reportedBy
    systemLocation
    incidentType
    severity
    l1Started
    l2
    l3
    closed
    resolutionTime
    slaViolated
    rootCause
    description
    createdAt
    status
    originalSeverity
    registeredByName
    deadline {
      deadlineAt
      hoursAllowed
      isOverdue
      remainingSeconds
    }
    correctiveActions {
      id
      description
      addedByName
      createdAt
    }
    severityHistory {
      id
      previousSeverity
      newSeverity
      reason
      changedByName
      createdAt
    }
    auditTrail {
      id
      action
      actorName
      details
      createdAt
    }
  }
`;

export const GET_INCIDENTS = gql`
  ${INCIDENT_FIELDS_FRAGMENT}
  query GetIncidents($search: String) {
    incidents(search: $search) {
      totalCount
      items {
        ...IncidentFields
      }
    }
  }
`;

export const CREATE_INCIDENT = gql`
  ${INCIDENT_FIELDS_FRAGMENT}
  mutation CreateIncident($input: IncidentInput!) {
    createIncident(input: $input) {
      __typename
      ... on IncidentType {
        ...IncidentFields
      }
      ... on ValidationError {
        message
      }
    }
  }
`;

export const UPDATE_INCIDENT = gql`
  ${INCIDENT_FIELDS_FRAGMENT}
  mutation UpdateIncident($id: ID!, $input: IncidentInput!) {
    updateIncident(id: $id, input: $input) {
      __typename
      ... on IncidentType {
        ...IncidentFields
      }
      ... on ValidationError {
        message
      }
    }
  }
`;

export const DELETE_INCIDENT = gql`
  mutation DeleteIncident($id: ID!) {
    deleteIncident(id: $id) {
      success
      message
    }
  }
`;

export const ADD_CORRECTIVE_ACTION = gql`
  ${INCIDENT_FIELDS_FRAGMENT}
  mutation AddCorrectiveAction($incidentId: ID!, $description: String!) {
    addCorrectiveAction(incidentId: $incidentId, description: $description) {
      __typename
      ... on IncidentType {
        ...IncidentFields
      }
      ... on ValidationError {
        message
      }
    }
  }
`;

export const CHANGE_INCIDENT_SEVERITY = gql`
  ${INCIDENT_FIELDS_FRAGMENT}
  mutation ChangeIncidentSeverity($incidentId: ID!, $newSeverity: String!, $reason: String!) {
    changeIncidentSeverity(incidentId: $incidentId, newSeverity: $newSeverity, reason: $reason) {
      __typename
      ... on IncidentType {
        ...IncidentFields
      }
      ... on ValidationError {
        message
      }
    }
  }
`;
