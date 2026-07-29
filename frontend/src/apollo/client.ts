import { ApolloClient, InMemoryCache, HttpLink, from } from "@apollo/client";
import { setContext } from "@apollo/client/link/context";
import { getCsrfToken } from "./csrf";

const httpLink = new HttpLink({
  uri: import.meta.env.VITE_API_URL ?? "http://localhost:8001/graphql",
  credentials: "include",
});

const csrfLink = setContext((_, prevContext) => ({
  headers: {
    ...prevContext.headers,
    "x-csrf-token": getCsrfToken(),
  },
}));

export const apolloClient = new ApolloClient({
  link: from([csrfLink, httpLink]),
  cache: new InMemoryCache(),
});
