export function useAuth() {
  return {
    session: { user: { id: "local-user", email: "demo@cybershield.ai" } },
    user:    { id: "local-user", email: "demo@cybershield.ai" },
    loading: false,
  };
}