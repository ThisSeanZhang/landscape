import { expect, test } from "./fixtures";

for (const kind of ["sites", "ips"] as const) {
  test(`searches Geo ${kind} in the rule editor and saves the selected source`, async ({
    page,
  }) => {
    const dns = kind === "sites";
    const base = dns ? "dns/rules" : "flow/dst_ip_rules";
    const saved = {
      t: "geo_key",
      name: "saved-source",
      key: "PRIVATE",
      attribute_key: "local",
      inverse: true,
    };
    const rule = {
      id: "office",
      name: "Office rule",
      index: 1,
      enable: true,
      flow_id: 0,
      source: [saved],
      upstream_id: "resolver",
      filter: "unfilter",
      mark: { action: { t: "direct" } },
    };
    const mock = (url: string, data: unknown) =>
      page.route("**/api/v1/" + url, (route) =>
        route.fulfill({ json: { data } }),
      );
    await mock("flow/rules", []);
    await mock(base + "/flow/0", [rule]);
    await mock(base + "/office", rule);
    if (dns) {
      await mock("dns/upstreams", []);
      await mock("dns/upstreams/resolver", {
        name: "Resolver",
        mode: { t: "plaintext" },
        ips: [],
      });
      await mock(base, rule);
      await mock("geo/sites/cache/attributes?*", ["new-attribute"]);
    }

    const calls: URL[] = [];
    page.on("request", (r) => {
      const url = new URL(r.url());
      if (url.pathname.startsWith("/api/v1/geo/")) calls.push(url);
    });
    await page.route("**/api/v1/geo/" + kind + "/cache/search?*", (route) => {
      const q = new URL(route.request().url()).searchParams.get("q");
      const data =
        q === "cn"
          ? [
              { name: "first", key: "CN" },
              { name: "second", key: "CN" },
            ]
          : [];
      return route.fulfill({ json: { data } });
    });

    await page.goto("/flow");
    await page
      .getByRole("button", {
        name: dns ? "DNS" : "Destination IP",
        exact: true,
      })
      .click();
    await page
      .getByRole("article", { name: rule.name })
      .getByRole("button", { name: "Edit" })
      .click();
    const picker = page.locator(".geo-rule-key");
    await expect(picker).toContainText(saved.name);
    await expect(picker).toContainText(saved.key);
    if (dns)
      await expect(page.locator(".geo-attribute")).toContainText(
        saved.attribute_key,
      );
    expect(calls).toHaveLength(0);

    await picker.click();
    await expect.poll(() => calls.length).toBe(1);
    const input = picker.locator("input");
    await input.fill("c");
    await input.fill("cn");
    const option = page
      .locator(".n-base-select-option")
      .filter({ hasText: "second" });
    await expect(option).toContainText("CN");
    await option.click();
    await expect(picker).toContainText("second");
    expect(
      calls.map((url) => [
        url.pathname,
        url.searchParams.get("q"),
        url.searchParams.get("limit"),
      ]),
    ).toEqual(
      ["", "cn"].map((q) => [`/api/v1/geo/${kind}/cache/search`, q, "30"]),
    );

    if (dns) {
      const attrs = page.locator(".geo-attribute");
      await expect(attrs).not.toContainText(saved.attribute_key);
      await attrs.click();
      await page
        .locator(".n-base-select-option")
        .filter({ hasText: "new-attribute" })
        .click();
      const last = calls[calls.length - 1];
      expect(last.pathname).toBe("/api/v1/geo/sites/cache/attributes");
      expect(Object.fromEntries(last.searchParams)).toEqual({
        name: "second",
        key: "CN",
      });
    }

    const [post] = await Promise.all([
      page.waitForRequest(
        (r) =>
          r.method() === "POST" &&
          new URL(r.url()).pathname ===
            "/api/v1/" + (dns ? base : base + "/office"),
      ),
      page.getByRole("button", { name: "Save", exact: true }).click(),
    ]);
    expect(post.postDataJSON().source).toEqual([
      {
        ...saved,
        name: "second",
        key: "CN",
        attribute_key: dns ? "new-attribute" : saved.attribute_key,
      },
    ]);
  });
}
