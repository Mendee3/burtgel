import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { useMutation, useQuery } from "@apollo/client/react";
import { BOOTSTRAP_SESSION, LOGIN, LOGOUT } from "../graphql/operations/auth";
import { setCsrfToken } from "../apollo/csrf";

export type Department = { slug: string; name: string };

export type CurrentUser = {
  id: string;
  username: string;
  email: string | null;
  displayName: string;
  role: string;
  mustChangePassword: boolean;
  department: Department | null;
};

type BootstrapData = { me: CurrentUser | null; csrfToken: string };

type LoginData = {
  login: {
    success: boolean;
    message: string;
    csrfToken: string;
    user: CurrentUser | null;
  };
};

type AuthContextValue = {
  user: CurrentUser | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<{ success: boolean; message: string }>;
  logout: () => Promise<void>;
};

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<CurrentUser | null>(null);
  const [ready, setReady] = useState(false);

  const { loading, data } = useQuery<BootstrapData>(BOOTSTRAP_SESSION, { fetchPolicy: "network-only" });
  const [loginMutation] = useMutation<LoginData>(LOGIN);
  const [logoutMutation] = useMutation(LOGOUT);

  useEffect(() => {
    if (!loading && data) {
      setCsrfToken(data.csrfToken ?? "");
      setUser(data.me);
      setReady(true);
    }
  }, [loading, data]);

  const login = async (username: string, password: string) => {
    const { data: result } = await loginMutation({ variables: { username, password } });
    const outcome = result?.login;
    if (outcome?.success && outcome.user) {
      setCsrfToken(outcome.csrfToken);
      setUser(outcome.user);
      return { success: true, message: "" };
    }
    return { success: false, message: outcome?.message ?? "Алдаа гарлаа." };
  };

  const logout = async () => {
    await logoutMutation();
    setCsrfToken("");
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, loading: !ready, login, logout }}>{children}</AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
