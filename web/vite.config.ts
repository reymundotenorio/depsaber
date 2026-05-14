import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const isGitHubPages = process.env.DEPLOY_TARGET === "github-pages";

export default defineConfig({
  base: isGitHubPages ? "/depsaber/" : "/",
  plugins: [react()],
});
