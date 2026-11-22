import type { Page } from "@playwright/test";
import { expect, test } from "./fixtures";

const source = { name: "AAA", key: "BBB+CCC" };
const similar = { name: "AAA", key: "BBB+CCC-DDD" };
const other = { name: "XXX", key: source.key };

async function mockGeo(page: Page, kind: "sites" | "ips") {
  const cache = `**/api/v1/geo/${kind}/cache`;
  await page.route(cache + "/search*", (route) => {
    const query = new URL(route.request().url()).searchParams;
    const data = [similar, other, source].filter(
      ({ name, key }) =>
        (!query.has("name") || query.get("name") === name) &&
        key.includes((query.get("key") ?? "").toUpperCase()),
    );
    return route.fulfill({ json: { data } });
  });
  await page.route(cache + "/detail?*", (route) => {
    const query = new URL(route.request().url()).searchParams;
    expect(Object.fromEntries(query)).toEqual(source);
    const values =
      kind === "sites"
        ? [{ match_type: "domain", value: "aaa.example", attributes: [] }]
        : [{ ip: "192.0.2.0", prefix: 24 }];
    return route.fulfill({ json: { data: { ...source, values } } });
  });
}

test("DNS GeoSite link filters the list and opens the referenced key", async ({
  page,
}) => {
  await mockGeo(page, "sites");
  const rule = {
    id: "aaa",
    name: "AAA rule",
    index: 1,
    flow_id: 0,
    enable: true,
    upstream_id: "bbb",
    filter: "unfilter",
    mark: { action: { t: "direct" } },
    source: [
      {
        t: "geo_key",
        ...source,
        key: source.key.toLowerCase(),
        attribute_key: "ccc",
        inverse: true,
      },
      { t: "config", match_type: "full", value: "bbb.example" },
    ],
  };
  await page.route("**/api/v1/flow/rules", (route) =>
    route.fulfill({ json: { data: [] } }),
  );
  await page.route("**/api/v1/dns/rules/flow/0", (route) =>
    route.fulfill({ json: { data: [rule] } }),
  );
  await page.route("**/api/v1/dns/upstreams/bbb", (route) =>
    route.fulfill({
      json: { data: { name: "BBB", mode: { t: "plaintext" }, ips: [] } },
    }),
  );

  await page.goto("/flow");
  await page.getByRole("button", { name: "DNS", exact: true }).click();
  const card = page.getByRole("article", { name: rule.name });
  await expect(card.getByRole("link")).toHaveCount(1);
  await card
    .getByRole("link", { name: "View GeoSite details for AAA/bbb+ccc" })
    .click();
  await expect(page).toHaveURL(/\/geo\/domain\?/);
  expect(Object.fromEntries(new URL(page.url()).searchParams)).toEqual({
    name: source.name,
    key: source.key.toLowerCase(),
    detail: "1",
  });
  await expect(page.getByRole("dialog")).toContainText("aaa.example");
  await page.reload();
  await expect(page.getByRole("dialog")).toContainText("aaa.example");
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  expect(Object.fromEntries(new URL(page.url()).searchParams)).toEqual({
    name: source.name,
    key: source.key.toLowerCase(),
  });
  await expect(
    page.getByRole("button", { name: "Details", exact: true }),
  ).toHaveCount(2);
  await expect(page.getByText(other.name, { exact: true })).toHaveCount(0);
  await page.goBack();
  await expect(page).toHaveURL(/\/flow$/);
});

test("GeoIP links support filtering alone and opening an exact key", async ({
  page,
}) => {
  await mockGeo(page, "ips");
  const url = "/geo/ip?" + new URLSearchParams(source);
  await page.goto(url);
  await expect(page.getByRole("dialog")).toHaveCount(0);
  const buttons = page.getByRole("button", { name: "Details", exact: true });
  await expect(buttons).toHaveCount(2);
  await buttons.first().click();
  await expect(page.getByRole("dialog")).toContainText("192.0.2.0/24");
  await page.goto(url + "&detail=1");
  await expect(page.getByRole("dialog")).toContainText("192.0.2.0/24");
  await page.goto("/geo/ip?key=BBB&detail=1");
  await expect(buttons).toHaveCount(3);
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await page.goto("/geo/ip?name=AAA&key=BBB&detail=1");
  await expect(buttons).toHaveCount(2);
  await expect(page.getByRole("dialog")).toHaveCount(0);
});
