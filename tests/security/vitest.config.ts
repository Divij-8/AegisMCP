import { defineProject } from "vitest/config";

export default defineProject({
  test: {
    environment: "node",
    include: ["**/*.test.ts"],
    // These suites share one PostgreSQL database and some exercise global
    // exhaustion/cleanup paths; serialize files so each sees a stable DB.
    fileParallelism: false,
  },
});
