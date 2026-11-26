import { expect, it } from "vitest";
import type { WanIPRuleSource } from "@landscape-router/types/api/schemas";
import { createWanIpRule } from "./mark";

it("preserves Geo rule attributes when loading a rule for editing", () => {
  const source: WanIPRuleSource = {
    t: "geo_key",
    key: "test",
    name: "local",
    inverse: true,
    attribute_key: "region",
  };
  const rule = createWanIpRule({ source: [source] });
  expect(rule.source).toEqual([source]);
  expect(rule.source[0]).not.toBe(source);
});
