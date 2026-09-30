import { defineProject } from "vitest/config";

export default defineProject({
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
    // Gateway package tests are DB-free by design: they always run in
    // no-persistence mode even when DATABASE_URL is exported for the
    // integration suites. (Empty string counts as unset in config.)
    env: {
      DATABASE_URL: "",
    },
  },
});
