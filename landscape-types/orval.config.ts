import { defineConfig } from "orval";

export default defineConfig({
  landscape: {
    input: {
      target: "./openapi.json",
    },
    output: {
      target: "./src/api/index.ts",
      schemas: "./src/api/schemas",
      client: "axios-functions",
      mode: "tags-split",
      override: {
        mutator: {
          path: "./src/api/mutator.ts",
          name: "customInstance",
        },
      },
    },
  },
});
