import { expect, test } from "./fixtures";

test("renders the login form in the server-configured language", async ({
  page,
}) => {
  await page.goto("/login");
  await expect(page.getByRole("button", { name: "Login" })).toBeVisible();
  await expect(page.getByText("Username", { exact: true })).toBeVisible();
});

test("submits credentials and shows the API error for a rejected login", async ({
  page,
}) => {
  await page.route("**/api/auth/login", (route) =>
    route.fulfill({
      status: 401,
      json: { message: "Invalid test credentials" },
    }),
  );

  await page.goto("/login");
  await page.locator('input[type="text"]').fill("e2e-user");
  await page.locator('input[type="password"]').fill("e2e-password");
  const request = page.waitForRequest("**/api/auth/login");
  await page.getByRole("button", { name: "Login" }).click();
  const login = await request;
  expect(login.method()).toBe("POST");
  expect(login.postDataJSON()).toEqual({
    username: "e2e-user",
    password: "e2e-password",
  });
  await expect(page.getByText("Invalid test credentials")).toBeVisible();
  await expect(page).toHaveURL(/\/login$/);
});
