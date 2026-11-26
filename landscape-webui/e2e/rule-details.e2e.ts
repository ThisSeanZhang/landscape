import type { CheckChainDnsResult } from "@landscape-router/types/api/schemas";
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

test("quick DNS queries fit on one row in narrow and wide drawers", async ({
  page,
}) => {
  await page.route("**/api/v1/flow/rules", (route) =>
    route.fulfill({ json: { data: [] } }),
  );
  await page.route("**/api/v1/dns/rules/flow/0", (route) =>
    route.fulfill({ json: { data: [] } }),
  );
  await page.goto("/flow");
  await page.getByRole("button", { name: "DNS", exact: true }).click();
  await page.getByRole("button", { name: "Run DNS query" }).click();
  const buttons = page.getByRole("button", {
    name: /^(IPv[46] (Baidu|USTC)|HTTPS Cloudflare)$/,
  });
  await expect(buttons).toHaveCount(5);
  for (const width of [320, 390, 1280]) {
    await page.setViewportSize({ width, height: 844 });
    for (const button of await buttons.all()) {
      await expect(button).toBeInViewport({ ratio: 1 });
    }
    const tops = await buttons.evaluateAll((buttons) =>
      buttons.map((button) => Math.round(button.getBoundingClientRect().top)),
    );
    expect(new Set(tops).size).toBe(1);
  }
});

test("DNS diagnostics display upstream, cached and redirected records", async ({
  page,
}) => {
  const record = {
    name: "edge.example.",
    rr_type: "A",
    ttl: 0,
    data: "192.0.2.42",
  };
  const cached = { ...record, ttl: 60, data: "192.0.2.10" };
  let result: CheckChainDnsResult = {
    rule_id: "test-rule",
    records: [record],
    cache_records: [cached],
  };
  await page.route("**/api/v1/flow/rules", (route) =>
    route.fulfill({ json: { data: [] } }),
  );
  await page.route("**/api/v1/dns/rules/flow/0", (route) =>
    route.fulfill({ json: { data: [] } }),
  );
  await page.route("**/api/v1/dns/rules/test-rule", (route) =>
    route.fulfill({
      json: { data: { name: "Test rule", upstream_id: "test-upstream" } },
    }),
  );
  await page.route("**/api/v1/dns/redirects/test-redirect", (route) =>
    route.fulfill({
      json: {
        data: {
          id: "test-redirect",
          name: "Office redirect",
          enable: true,
          answer_mode: "static_ips",
          apply_flows: [],
          result_info: [record.data],
          match_rules: [],
        },
      },
    }),
  );
  await page.route("**/api/v1/dns/service/check?*", (route) =>
    route.fulfill({ json: { data: result } }),
  );
  await page.route("**/api/v1/dns/service/cache?*", (route) =>
    route.fulfill({ json: { data: { ...result, cache_records: null } } }),
  );
  await page.route("**/api/v1/dns/service/cache/refresh?*", (route) =>
    route.fulfill({ json: { data: { ...result, cache_records: [record] } } }),
  );

  await page.goto("/flow");
  await page.getByRole("button", { name: "DNS", exact: true }).click();
  await page.getByRole("button", { name: "Run DNS query" }).click();
  const query = page.getByRole("button", { name: "IPv4 Baidu" });
  const refresh = page.getByRole("button", { name: "Force refresh cache" });
  const remove = page.getByRole("button", { name: "Delete Cache" });
  await expect(refresh).toHaveCount(0);
  await expect(remove).toHaveCount(0);
  await query.click();

  const matchedCard = page.getByRole("article", { name: "Test rule" });
  await expect(
    page.getByRole("heading", { name: "Matched DNS rule" }),
  ).toBeVisible();
  await expect(matchedCard.getByRole("button", { name: "Edit" })).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "DNS Upstream Query Results" }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "DNS Internal Cache Results" }),
  ).toBeVisible();
  await expect(page.locator("li code")).toHaveText([record.data, cached.data]);
  await expect(page.getByText("TTL 0 s", { exact: true })).toBeVisible();

  await page.setViewportSize({ width: 320, height: 740 });
  for (const data of [record.data, cached.data]) {
    const row = page.getByRole("button", { name: data });
    await expect(row).toHaveAttribute("aria-expanded", "false");
    const bounds = await row
      .locator(":scope > *")
      .evaluateAll((fields) =>
        fields.map((field) => field.getBoundingClientRect().toJSON()),
      );
    expect(Math.max(...bounds.map((field) => field.top))).toBeLessThan(
      Math.min(...bounds.map((field) => field.bottom)),
    );
    expect(bounds[bounds.length - 1].right).toBeLessThanOrEqual(320);
  }
  for (const [heading, button] of [
    ["DNS Upstream Query Results", refresh],
    ["DNS Internal Cache Results", remove],
  ] as const) {
    await button.scrollIntoViewIfNeeded();
    const title = (await page
      .getByRole("heading", { name: heading })
      .boundingBox())!;
    const action = (await button.boundingBox())!;
    expect(action.x).toBeGreaterThanOrEqual(title.x + title.width);
    expect(action.y + action.height / 2).toBeCloseTo(
      title.y + title.height / 2,
      0,
    );
    expect(action.x + action.width).toBeLessThanOrEqual(320);
  }
  const input = page.getByPlaceholder(/Enter a domain/);
  await input.fill("draft.example");
  for (const [button, method, path] of [
    [remove, "DELETE", "/api/v1/dns/service/cache"],
    [refresh, "POST", "/api/v1/dns/service/cache/refresh"],
  ] as const) {
    await button.click();
    const [request] = await Promise.all([
      page.waitForRequest(
        (req) =>
          req.method() === method && new URL(req.url()).pathname === path,
      ),
      page.getByRole("button", { name: "Confirm", exact: true }).click(),
    ]);
    const params = new URL(request.url()).searchParams;
    expect(params.get("domain")).toBe("www.baidu.com");
    expect(params.get("record_type")).toBe("A");
    expect(params.get("flow_id")).toBe("0");
    await expect(input).toHaveValue("draft.example");
    if (method === "DELETE") {
      await expect(page.getByText("No cache entry")).toBeVisible();
    } else {
      await expect(page.locator("li code")).toHaveText([
        record.data,
        record.data,
      ]);
    }
  }
  await page.setViewportSize({ width: 390, height: 844 });
  result = { rule_id: "test-rule", records: [] };
  await query.click();
  await expect(page.getByText("No records returned")).toBeVisible();
  await expect(page.getByText("No cache entry")).toBeVisible();

  result = { redirect_id: "test-redirect", records: [record] };
  await query.click();
  const redirectHeading = page.getByRole("heading", {
    name: "Matched redirect rule",
  });
  await expect(redirectHeading).toBeVisible();
  await expect(refresh).toHaveCount(0);
  await expect(remove).toHaveCount(0);
  await expect(
    page.getByText("Office redirect", { exact: true }),
  ).toBeVisible();
  await expect(page.getByText("Static IP list", { exact: true })).toBeVisible();
  await expect(matchedCard).toHaveCount(0);

  const longValue = "1 . ech=" + "a".repeat(256);
  result = {
    dynamic_redirect_source: "test",
    records: [{ ...record, rr_type: "HTTPS", data: longValue }],
  };
  await query.click();
  await expect(redirectHeading).toHaveCount(0);
  await expect(
    page.getByRole("heading", { name: "Domain Redirect Results" }),
  ).toBeVisible();
  const value = page.locator("li code");
  await expect(value).toHaveText(longValue);
  const recordButton = page.getByRole("button", { name: longValue });
  expect(await value.evaluate((el) => el.scrollWidth > el.clientWidth)).toBe(
    true,
  );
  await recordButton.focus();
  await page.keyboard.press("Enter");
  await expect(recordButton).toHaveAttribute("aria-expanded", "true");
  expect(
    await value.evaluate((el) => el.scrollWidth <= el.clientWidth + 1),
  ).toBe(true);
  const bounds = await value.boundingBox();
  expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(390);
  await recordButton.click();
  await expect(recordButton).toHaveAttribute("aria-expanded", "false");
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
