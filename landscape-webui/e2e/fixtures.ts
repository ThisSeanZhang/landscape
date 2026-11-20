import { test as base } from "@playwright/test";

export { expect } from "@playwright/test";

export const test = base.extend({
  page: async ({ page }, use) => {
    // Only explicitly mocked API requests may complete during browser tests.
    await page.route("**/api/**", (route) => route.abort());
    await page.routeWebSocket("**/api/**", () => {});
    await page.route("**/api/v1/system/config/ui", (route) =>
      route.fulfill({ json: { data: { language: "en" } } }),
    );
    await use(page);
  },
});
