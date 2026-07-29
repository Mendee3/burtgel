import { gql } from "@apollo/client";

export const ASSET_FIELDS_FRAGMENT = gql`
  fragment AssetFields on AssetType {
    id
    assetName
    description
    assetType
    assetGroupCode
    hasPersonalData
    hasSensitiveData
    owner
    custodian
    location
    retentionPeriod
    confidentiality
    integrityImpact
    availabilityImpact
    assetValue
    assetCategory
  }
`;

export const GET_DEPARTMENTS = gql`
  query GetDepartments {
    departments {
      id
      slug
      name
    }
  }
`;

export const GET_DEPARTMENT_ASSETS = gql`
  ${ASSET_FIELDS_FRAGMENT}
  query GetDepartmentAssets($departmentSlug: String!, $search: String) {
    assetPermissions(departmentSlug: $departmentSlug) {
      canRead
      canUpdate
      editableFields
    }
    assets(departmentSlug: $departmentSlug, search: $search) {
      totalCount
      items {
        ...AssetFields
      }
    }
  }
`;

export const CREATE_ASSET = gql`
  ${ASSET_FIELDS_FRAGMENT}
  mutation CreateAsset($departmentSlug: String!, $input: AssetInput!) {
    createAsset(departmentSlug: $departmentSlug, input: $input) {
      __typename
      ... on AssetType {
        ...AssetFields
      }
      ... on ValidationError {
        message
      }
    }
  }
`;

export const UPDATE_ASSET = gql`
  ${ASSET_FIELDS_FRAGMENT}
  mutation UpdateAsset($departmentSlug: String!, $id: ID!, $input: AssetInput!) {
    updateAsset(departmentSlug: $departmentSlug, id: $id, input: $input) {
      __typename
      ... on AssetType {
        ...AssetFields
      }
      ... on ValidationError {
        message
      }
    }
  }
`;

export const DELETE_ASSET = gql`
  mutation DeleteAsset($departmentSlug: String!, $id: ID!) {
    deleteAsset(departmentSlug: $departmentSlug, id: $id) {
      success
      message
    }
  }
`;
