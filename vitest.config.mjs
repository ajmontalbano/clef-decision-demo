import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest({
      main: "./src/index.js",
      miniflare: { compatibilityDate: "2026-10-07" }
    })
  ],
  test: {
    include: ["test/**/*.spec.js"]
  }
});
