import { Navigate, Route, Routes } from "react-router-dom";
import { ChangePasswordPage } from "./routes/ChangePasswordPage";
import { IncidentRegisterPage } from "./routes/IncidentRegisterPage";
import { LoginPage } from "./routes/LoginPage";
import { TopNav } from "./components/layout/TopNav";
import { useAuth } from "./lib/auth";
import { mn } from "./i18n/mn";

function App() {
  const { user, loading } = useAuth();

  if (loading) {
    return <p className="p-6 text-sm text-muted">{mn.loading}</p>;
  }
  if (!user) {
    return <LoginPage />;
  }
  if (user.mustChangePassword) {
    return <ChangePasswordPage onDone={() => window.location.reload()} />;
  }

  return (
    <div className="min-h-screen bg-bg">
      <TopNav />
      <Routes>
        <Route path="/" element={<IncidentRegisterPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </div>
  );
}

export default App;
