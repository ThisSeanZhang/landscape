import type { Locator } from "@playwright/test";
import { expect, test } from "./fixtures";

test.use({ viewport: { width: 390, height: 844 } });

async function expectShortMatchesToShareRow(card: Locator) {
  const rows = await card
    .getByRole("listitem")
    .evaluateAll((items) =>
      items.slice(-3).map((item) => item.getBoundingClientRect().top),
    );
  expect(rows[1]).toBeGreaterThan(rows[0]);
  expect(rows[2]).toBe(rows[1]);
}

async function expectScrollableMatches(card: Locator, count: number) {
  const heading = `Match rules (${count} total)`;
  await expect(card.getByRole("heading", { name: heading })).toBeVisible();
  const list = card.getByRole("list", { name: heading });
  const items = list.getByRole("listitem");
  await expect(items).toHaveCount(count);
  await expect(items.last()).not.toBeInViewport({ ratio: 0.97 });
  await list.press("End");
  await expect(items.last()).toBeInViewport({ ratio: 0.97 });
  await list.press("Home");
  await expect(items.first()).toBeInViewport({ ratio: 0.97 });
}

test("DNS rule cards show settings and scroll long match lists on mobile", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 600 });
  const pattern = "internal-".repeat(28) + "example$";
  const rule = {
    id: "office",
    name: "Office DNS",
    index: 10,
    flow_id: 0,
    enable: false,
    upstream_id: "office-resolver",
    filter: "only_ipv6",
    mark: { action: { t: "direct" } },
    source: [
      { t: "config", match_type: "full", value: "office.example" },
      {
        t: "geo_key",
        name: "sites",
        key: "office",
        attribute_key: "local",
        inverse: true,
      },
      { t: "config", match_type: "regex", value: pattern },
      { t: "config", match_type: "full", value: "a.dev" },
      { t: "config", match_type: "full", value: "b.dev" },
    ],
  };
  await page.route("**/api/v1/flow/rules", (route) =>
    route.fulfill({ json: { data: [] } }),
  );
  await page.route("**/api/v1/dns/rules/flow/0", (route) =>
    route.fulfill({
      json: {
        data: [
          rule,
          {
            ...rule,
            id: "default",
            name: "Fallback",
            index: 20,
            enable: true,
            source: [],
          },
          {
            ...rule,
            id: "single",
            name: "One domain",
            source: rule.source.slice(0, 1),
          },
        ],
      },
    }),
  );
  await page.route("**/api/v1/dns/upstreams/office-resolver", (route) =>
    route.fulfill({
      json: {
        data: { name: "Office resolver", mode: { t: "plaintext" }, ips: [] },
      },
    }),
  );
  await page.goto("/flow");
  await page.getByRole("button", { name: "DNS", exact: true }).click();
  const card = page.getByRole("article", { name: rule.name });
  await card.hover();
  const thumb = page.locator(
    ".drawer-scroll-gutter > .n-scrollbar-rail--vertical .n-scrollbar-rail__scrollbar",
  );
  await expect(thumb).toBeVisible();
  const cardBounds = (await card.boundingBox())!;
  expect((await thumb.boundingBox())!.x).toBeGreaterThan(
    cardBounds.x + cardBounds.width,
  );
  const header = card.locator("header");
  const disabled = header.getByRole("button", {
    name: "Disabled",
    exact: true,
  });
  await disabled.click();
  await expect(page.getByText("Disabled", { exact: true })).toBeVisible();
  await disabled.click();
  await expect(card.getByText("Office resolver")).toBeVisible();
  const [title, status, upstream, edit, remove] = await Promise.all(
    [
      header.getByRole("heading", { name: rule.name }),
      disabled,
      header.getByText("Office resolver", { exact: true }),
      header.getByRole("button", { name: "Edit" }),
      header.getByRole("button", { name: "Delete" }),
    ].map((item) =>
      item.evaluate((el) => {
        const box = el.getBoundingClientRect();
        return box.y + box.height / 2;
      }),
    ),
  );
  expect(Math.abs(title - status)).toBeLessThan(4);
  expect(Math.abs(title - edit)).toBeLessThan(4);
  expect(upstream).toBeGreaterThan(edit);
  expect(edit).toBeCloseTo(remove);
  await expect(card.getByText("IPv6 only")).toBeVisible();
  await expect(card.getByText("sites/office@local")).toBeVisible();
  await expect(card.getByText("Inverse")).toBeVisible();
  const fallback = page.getByRole("article", { name: "Fallback" });
  await expect(
    fallback.getByRole("heading", { name: "Match rules (0 total)" }),
  ).toBeVisible();
  await expect(fallback.getByText("Matches all domains")).toBeVisible();
  await expect(
    fallback.getByRole("button", { name: "Enabled", exact: true }),
  ).toBeVisible();
  const single = page.getByRole("article", { name: "One domain" });
  await expect(
    single
      .getByRole("list", { name: "Match rules (1 total)" })
      .getByRole("listitem"),
  ).toHaveCount(1);
  await expect(
    single.locator(".source-scroll .n-scrollbar-rail__scrollbar"),
  ).toHaveCount(0);
  await expectScrollableMatches(card, rule.source.length);
  const value = card.getByText(pattern);
  expect(
    await value.evaluate((el) => el.getBoundingClientRect().right),
  ).toBeLessThanOrEqual(390);
  await expectShortMatchesToShareRow(card);
  await page.setViewportSize({ width: 1280, height: 844 });
  await expectShortMatchesToShareRow(card);
  await card.getByRole("button", { name: "Delete" }).click();
  await expect(page.getByText("Confirm deletion?")).toBeVisible();
});

test("destination rules show routing, scrollable matches and masked IPs", async ({
  page,
}) => {
  const geoKey = "regional-".repeat(12);
  const source = [
    { t: "config", ip: "2001:db8:abcd::", prefix: 48 },
    {
      t: "geo_key",
      name: "database",
      key: geoKey,
      inverse: true,
      attribute_key: "group",
    },
    { t: "config", ip: "192.0.2.0", prefix: 24 },
    { t: "config", ip: "10.0.0.0", prefix: 8 },
  ];
  const rule = {
    id: "office",
    name: "Office network",
    remark: "Private subnets",
    index: 10,
    mark: { action: { t: "direct" } },
    source,
  };
  const fallback = {
    id: "empty",
    remark: "Reserved",
    index: 20,
    enable: false,
  };
  let deleted = false;
  await page.route("**/api/v1/flow/rules", (route) =>
    route.fulfill({ json: { data: [] } }),
  );
  await page.route("**/api/v1/flow/dst_ip_rules/flow/0", (route) =>
    route.fulfill({
      json: { data: deleted ? [fallback] : [rule, fallback] },
    }),
  );
  await page.route("**/api/v1/flow/dst_ip_rules/office", (route) => {
    if (route.request().method() === "DELETE") {
      deleted = true;
      return route.fulfill({ status: 204 });
    }
    return route.fulfill({ json: { data: rule } });
  });
  await page.goto("/flow");
  const open = page.getByRole("button", {
    name: "Destination IP",
    exact: true,
  });
  await open.click();
  const card = page.getByRole("article", { name: rule.name });
  const values = card.getByRole("list").locator("code");
  await expect(values).toHaveText([
    "2001:db8:abcd::/48",
    `database/${geoKey}`,
    "192.0.2.0/24",
    "10.0.0.0/8",
  ]);
  await expect(card.getByRole("button", { name: "Enabled" })).toBeVisible();
  await expect(card.getByText("Default flow egress")).toBeVisible();
  await expect(card.getByText(rule.remark, { exact: false })).toBeVisible();
  const empty = page.getByRole("article", { name: fallback.remark });
  await expect(empty.getByRole("button", { name: "Disabled" })).toBeVisible();
  await expect(empty.getByText(/has no effect/)).toBeVisible();
  await expectScrollableMatches(card, source.length);
  await expectShortMatchesToShareRow(card);
  await page.setViewportSize({ width: 1280, height: 844 });
  await expectShortMatchesToShareRow(card);
  await expect(page.getByText("@group", { exact: true })).toBeVisible();
  await expect(page.getByText("Inverse", { exact: true })).toBeVisible();
  for (const width of [320, 390, 1280]) {
    await page.setViewportSize({ width, height: 844 });
    const cardBounds = (await card.boundingBox())!;
    const geoBounds = (await values.nth(1).boundingBox())!;
    expect(geoBounds.x + geoBounds.width).toBeLessThanOrEqual(
      cardBounds.x + cardBounds.width,
    );
    expect(cardBounds.x + cardBounds.width).toBeLessThanOrEqual(width);
  }
  await card.getByRole("button", { name: "Edit" }).click();
  const editor = page
    .getByRole("dialog")
    .filter({ has: page.getByRole("button", { name: "Save" }) });
  await expect(editor.getByRole("textbox").first()).toHaveValue(rule.name);
  await editor.getByRole("button", { name: "Cancel" }).click();
  await page.evaluate(() =>
    localStorage.setItem(
      "front_end",
      JSON.stringify({ presentation_mode: true }),
    ),
  );
  await page.reload();
  await open.click();
  await expect(values.first()).toHaveText("2001:db8:*:*:*/48");
  await expect(values.nth(1)).toHaveText(/^dat\*+\/\*+.{5}\*+$/);
  await expect(page.getByText("@gro*****", { exact: true })).toBeVisible();
  await card.getByRole("button", { name: "Delete" }).click();
  await expect(page.getByText("Confirm deletion?")).toBeVisible();
  await page.getByRole("button", { name: /^(Confirm|OK|Yes)$/ }).click();
  await expect(card).toHaveCount(0);
  await expect(empty).toBeVisible();
});
