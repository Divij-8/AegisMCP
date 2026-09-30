import { defineProject } from "vitest/config";

export default defineProject({
  test: {
    environment: "node",
    include: ["**/*.test.ts"],
    // These suites share one PostgreSQL database and some mutate global rows
    // (e.g. bulk-disable/delete). Running files in parallel made cross-suite
    // interference possible; serialize them so each file sees a stable DB.
    fileParallelism: false,
  },
});
