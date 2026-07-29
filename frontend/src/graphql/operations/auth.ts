import { gql } from "@apollo/client";

export const BOOTSTRAP_SESSION = gql`
  query BootstrapSession {
    me {
      id
      username
      email
      displayName
      role
      mustChangePassword
      department {
        slug
        name
      }
    }
    csrfToken
  }
`;

export const LOGIN = gql`
  mutation Login($username: String!, $password: String!) {
    login(username: $username, password: $password) {
      success
      message
      csrfToken
      user {
        id
        username
        email
        displayName
        role
        mustChangePassword
        department {
          slug
          name
        }
      }
    }
  }
`;

export const LOGOUT = gql`
  mutation Logout {
    logout
  }
`;

export const CHANGE_PASSWORD = gql`
  mutation ChangePassword($currentPassword: String!, $newPassword: String!) {
    changePassword(currentPassword: $currentPassword, newPassword: $newPassword) {
      success
      message
    }
  }
`;
