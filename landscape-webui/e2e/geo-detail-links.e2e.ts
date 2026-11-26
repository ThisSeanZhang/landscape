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
        ? ["aaa.example", "other.example"].map((value) => ({
            match_type: "domain",
            value,
            attributes: [],
          }))
        : [
            { ip: "192.0.2.0", prefix: 24 },
            { ip: "2001:db8::", prefix: 32 },
          ];
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
  const details = page.getByRole("region", { name: "Rule Details" });
  await expect(details).toContainText("aaa.example");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await page.reload();
  await expect(details).toContainText("aaa.example");
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.getByRole("dialog")).toContainText("aaa.example");
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  expect(Object.fromEntries(new URL(page.url()).searchParams)).toEqual({
    name: source.name,
    key: source.key.toLowerCase(),
  });
  await expect(
    page.getByRole("button", { name: /View GeoSite details/ }),
  ).toHaveCount(2);
  await expect(page.getByText(other.name, { exact: true })).toHaveCount(0);
  await page.goBack();
  await expect(page).toHaveURL(/\/flow$/);
});

test("only GeoIP entries in destination rules link to exact key details", async ({
  page,
}) => {
  await mockGeo(page, "ips");
  const address = "192.0.2.1";
  const rule = {
    id: "aaa",
    name: "AAA rule",
    index: 1,
    flow_id: 0,
    enable: true,
    mark: { action: { t: "direct" } },
    source: [
      {
        t: "geo_key",
        ...source,
        key: source.key.toLowerCase(),
        inverse: false,
      },
      { t: "config", ip: address, prefix: 32 },
    ],
  };
  await page.route("**/api/v1/flow/rules", (route) =>
    route.fulfill({ json: { data: [] } }),
  );
  await page.route("**/api/v1/flow/dst_ip_rules/flow/0", (route) =>
    route.fulfill({ json: { data: [rule] } }),
  );
  await page.goto("/flow");
  await page
    .getByRole("button", { name: "Destination IP", exact: true })
    .click();
  const card = page.getByRole("article", { name: rule.name });
  await expect(card.getByText(address + "/32", { exact: true })).toBeVisible();
  await expect(card.getByRole("link")).toHaveCount(1);
  await card
    .getByRole("link", { name: "View GeoIP details for AAA/bbb+ccc" })
    .click();
  const details = page.getByRole("region", { name: "Rule Details" });
  const buttons = page.getByRole("button", { name: /View GeoIP details/ });
  await expect(details).toContainText("192.0.2.0/24");
  expect(Object.fromEntries(new URL(page.url()).searchParams)).toEqual({
    name: source.name,
    key: source.key.toLowerCase(),
    detail: "1",
  });
  await expect(buttons).toHaveCount(2);
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.getByRole("dialog")).toContainText("2001:db8::/32");
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await page.goto("/geo/ip?key=BBB&detail=1");
  await expect(buttons).toHaveCount(3);
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await page.goto("/geo/ip?name=AAA&key=BBB&detail=1");
  await expect(buttons).toHaveCount(2);
  await expect(page.getByRole("dialog")).toHaveCount(0);
});

test("IPv4 and IPv6 lookups filter GeoIP keys and expose matching networks", async ({
  page,
}) => {
  await mockGeo(page, "ips");
  const ipv4 = "192.0.2.1";
  const ipv6 = "2001:db8::1";
  await page.route("**/geo/ips/cache/lookup?*", (route) => {
    const ip = new URL(route.request().url()).searchParams.get("ip");
    const keys = ip === ipv4 ? [source] : ip === ipv6 ? [source, other] : [];
    const network =
      ip === ipv4
        ? { ip: "192.0.2.0", prefix: 24 }
        : { ip: "2001:db8::", prefix: 32 };
    return route.fulfill({
      json: { data: keys.map((key) => ({ key, values: [network] })) },
    });
  });
  await page.goto("/geo/ip?ip=" + ipv4);
  const input = page.getByRole("textbox", { name: "Lookup IP" });
  const list = page.getByRole("region", { name: "GeoIP keys" });
  const entries = list.getByRole("button");
  const details = page.getByRole("region", { name: "Rule Details" });
  await expect(input).toHaveValue(ipv4);
  await expect(entries).toHaveCount(1);
  await expect(details).toContainText("Select a GeoIP key");
  await input.fill(ipv6);
  await input.press("Enter");
  await expect(entries).toHaveCount(2);
  expect(new URL(page.url()).searchParams.get("ip")).toBe(ipv6);
  await list
    .getByRole("button", {
      name: "View GeoIP details for AAA/BBB+CCC",
      exact: true,
    })
    .click();
  await expect(details).toContainText("2001:db8::/32");
  await expect(details).not.toContainText("192.0.2.0/24");
  await details.getByText("All networks", { exact: true }).click();
  await expect(details).toContainText("192.0.2.0/24");
  await page.getByRole("textbox", { name: "Select geo name" }).click();
  await page
    .locator(".n-base-select-option")
    .filter({ hasText: other.name })
    .click();
  await expect(entries).toHaveCount(1);
  await expect(entries).toContainText(other.name);
  await expect(details).toContainText("Select a GeoIP key");
  await input.fill("2001:db8:1::1");
  await input.press("Enter");
  await expect(list).toContainText("No matching Geo rules");
});

test("domain and source filters narrow the same GeoSite list", async ({
  page,
}) => {
  await mockGeo(page, "sites");
  let lookups = 0;
  let detailRequests = 0;
  page.on("request", (request) => {
    if (new URL(request.url()).pathname.endsWith("/sites/cache/detail"))
      detailRequests++;
  });
  await page.route("**/geo/sites/cache/lookup?*", (route) => {
    lookups++;
    const data =
      new URL(route.request().url()).searchParams.get("domain") ===
      "www.aaa.example"
        ? [source, other].map((key) => ({
            key,
            values: [
              {
                match_type: "domain",
                value: "aaa.example",
                attributes: [],
              },
            ],
          }))
        : [];
    return route.fulfill({ json: { data } });
  });
  await page.goto("/geo/domain");
  const list = page.getByRole("region", { name: "GeoSite keys" });
  const details = page.getByRole("region", { name: "Rule Details" });
  const entries = list.getByRole("button");
  await expect(entries).toHaveCount(3);
  await expect(details).toContainText("Select a GeoSite key");
  const input = page.getByRole("textbox", { name: "Lookup Domain" });
  await input.fill("https://WWW.AAA.example:443/path");
  await input.press("Enter");
  await expect(page).toHaveURL(/domain=www\.aaa\.example/);
  await expect(entries).toHaveCount(2);
  expect(lookups).toBe(1);
  await list
    .getByRole("button", {
      name: "View GeoSite details for AAA/BBB+CCC",
      exact: true,
    })
    .click();
  await expect(details).toContainText("aaa.example");
  expect(detailRequests).toBe(0);
  await details.getByText("All rules", { exact: true }).click();
  await expect(details).toContainText("other.example");
  expect(detailRequests).toBe(1);
  await details.getByText("Matching rules", { exact: true }).click();
  await expect(details).toContainText("aaa.example");
  const filters = page.getByRole("form", { name: "Filters" });
  await filters.getByRole("textbox", { name: "Select geo name" }).click();
  await page
    .locator(".n-base-select-option")
    .filter({ hasText: "XXX" })
    .click();
  await expect(entries).toHaveCount(1);
  await expect(entries).toContainText("XXX");
  await expect(details).toContainText("Select a GeoSite key");
  await filters.getByRole("textbox", { name: "Filter key" }).click();
  await page
    .locator(".n-base-select-option")
    .filter({ hasText: source.key })
    .click();
  await expect
    .poll(() => new URL(page.url()).searchParams.get("key"))
    .toBe(source.key);
  expect(lookups).toBe(1);
  await input.fill("absent.example");
  await input.press("Enter");
  await expect(list).toContainText("No matching Geo rules");
  await input.fill("");
  await input.press("Enter");
  await expect(entries).toHaveCount(1);
  expect(Object.fromEntries(new URL(page.url()).searchParams)).toEqual(other);
});
