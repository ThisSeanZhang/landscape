import {
  alignPlannerUnitRangeToPrefix,
  buildPrefixPlannerViewFromGroups,
  inspectPlannerUnitRangeCandidateFromGroups,
  plannerSelectionIsConflict,
  plannerUnitLabels,
  poolIndexFromPlannerUnitStart,
  shouldResetStalePlannerSelection,
  type BuildGroupPlannerOptions,
  type PlannerUnit,
} from "@/lib/ipv6_planner";
import type {
  LanIPv6ServiceConfigV2,
  LanPrefixGroupConfig,
} from "@landscape-router/types/api/schemas";
import { describe, expect, it } from "vitest";

function staticGroup(
  groupId: string,
  basePrefix: string,
  entries: Pick<LanPrefixGroupConfig, "ra" | "na" | "pd">,
): LanPrefixGroupConfig {
  return {
    group_id: groupId,
    parent: {
      t: "static",
      base_prefix: basePrefix,
      parent_prefix_len: 56,
    },
    ra: entries.ra ?? null,
    na: entries.na ?? null,
    pd: entries.pd ?? null,
  };
}

function lanConfig(
  ifaceName: string,
  groups: LanPrefixGroupConfig[],
): LanIPv6ServiceConfigV2 {
  return {
    iface_name: ifaceName,
    enable: true,
    config: {
      mode: "slaac_dhcpv6",
      prefix_groups: groups,
      ra_flag: {
        home_agent: false,
        managed_address_config: true,
        nd_proxy: false,
        other_config: true,
        prf: 0,
        reserved: 0,
      },
    },
  };
}

function plannerOptions(
  editGroup: LanPrefixGroupConfig,
  selectedKind: "ra" | "na" | "pd",
  otherConfigsV2: LanIPv6ServiceConfigV2[] = [],
  currentGroups: LanPrefixGroupConfig[] = [editGroup],
): BuildGroupPlannerOptions {
  return {
    currentIfaceName: "lan-current",
    currentGroups,
    currentMode: "slaac_dhcpv6",
    otherConfigsV2,
    editGroup,
    selectedKind,
    prefixInfos: new Map(),
    expectedPdLens: new Map(),
    draftPdPoolLen: editGroup.pd?.pool_len ?? 64,
  };
}

describe("IPv6 prefix planner occupancy", () => {
  it("aligns a covered range from slot 0 instead of moving past WAN", () => {
    const aligned = alignPlannerUnitRangeToPrefix(1, 16, 60);

    expect(aligned).toEqual({ unitStart: 0, unitEnd: 16 });
  });

  it("rejects a pool-length realignment that would cover WAN slot 0", () => {
    const group = staticGroup("pd-realign", "fd00::", {
      pd: { pool_len: 64, start_index: 1, end_index: 15 },
    });
    const aligned = alignPlannerUnitRangeToPrefix(1, 16, 60)!;
    const candidate = inspectPlannerUnitRangeCandidateFromGroups(
      plannerOptions(group, "pd"),
      aligned.unitStart,
      aligned.unitEnd - aligned.unitStart,
    );

    expect(candidate.selectedStatus).toBe("wan_reserved");
    expect(candidate.canSave).toBe(false);
  });

  it("keeps a pool-length realignment that is already past WAN", () => {
    expect(alignPlannerUnitRangeToPrefix(16, 32, 60)).toEqual({
      unitStart: 16,
      unitEnd: 32,
    });
  });

  it("rejects unsupported pool index conversions", () => {
    expect(() => poolIndexFromPlannerUnitStart(65, 0)).toThrow(RangeError);
  });

  it.each([
    {
      name: "RA index 0",
      group: staticGroup("ra-wan", "fd00::", {
        ra: { pool_index: 0 },
      }),
      kind: "ra" as const,
    },
    {
      name: "IA_NA index 0",
      group: staticGroup("na-wan", "fd00::", {
        na: { pool_index: 0 },
      }),
      kind: "na" as const,
    },
    {
      name: "IA_PD /60 index 0",
      group: staticGroup("pd-wan", "fd00::", {
        pd: { pool_len: 60, start_index: 0, end_index: 0 },
      }),
      kind: "pd" as const,
    },
  ])("rejects $name through the WAN occupancy record", ({ group, kind }) => {
    const view = buildPrefixPlannerViewFromGroups(plannerOptions(group, kind));

    expect(view.selectedStatus).toBe("wan_reserved");
    expect(view.canSave).toBe(false);
    expect(view.saveError).toBe("lan_ipv6.planner_save_error_wan_reserved");
  });

  it("allows IA_PD /60 index 1 after the WAN slot", () => {
    const group = staticGroup("pd-available", "fd00::", {
      pd: { pool_len: 60, start_index: 1, end_index: 1 },
    });

    const view = buildPrefixPlannerViewFromGroups(plannerOptions(group, "pd"));

    expect(view.selectedUnitStart).toBe(16);
    expect(view.selectedUnitSpan).toBe(16);
    expect(view.selectedStatus).toBe("available");
    expect(view.canSave).toBe(true);
  });

  it("detects another LAN PD range overlapping the current RA index", () => {
    const current = staticGroup("current-ra", "fd00::", {
      ra: { pool_index: 20 },
    });
    const other = staticGroup("other-pd", "2001:db8::", {
      pd: { pool_len: 60, start_index: 1, end_index: 1 },
    });

    const view = buildPrefixPlannerViewFromGroups(
      plannerOptions(current, "ra", [lanConfig("lan-other", [other])]),
    );

    expect(view.selectedStatus).toBe("conflict");
    expect(view.canSave).toBe(false);
    expect(view.selectedOccupants).toEqual([
      expect.objectContaining({
        ifaceName: "lan-other",
        scope: "other",
        serviceKind: "pd",
        effectiveIndex: 1,
        effectiveEndIndex: 1,
        poolLen: 60,
        conflictsWithSelection: true,
      }),
    ]);
  });

  it("allows RA and IA_NA to share an index in the same current group", () => {
    const group = staticGroup("shared", "fd00::", {
      ra: { pool_index: 7 },
      na: { pool_index: 7 },
    });

    const view = buildPrefixPlannerViewFromGroups(plannerOptions(group, "ra"));

    expect(view.selectedStatus).toBe("shared");
    expect(view.canSave).toBe(true);
    expect(view.selectedOccupants).toEqual([
      expect.objectContaining({
        scope: "current",
        groupId: "shared",
        serviceKind: "na",
        conflictsWithSelection: false,
      }),
    ]);
  });

  it("gives WAN conflict precedence over an overlapping LAN record", () => {
    const current = staticGroup("current-wan", "fd00::", {
      ra: { pool_index: 0 },
    });
    const other = staticGroup("legacy-wan", "2001:db8::", {
      na: { pool_index: 0 },
    });

    const view = buildPrefixPlannerViewFromGroups(
      plannerOptions(current, "ra", [lanConfig("lan-other", [other])]),
    );

    expect(view.selectedStatus).toBe("wan_reserved");
    expect(view.canSave).toBe(false);
    expect(view.selectedOccupants).toEqual([
      expect.objectContaining({
        ifaceName: "lan-other",
        serviceKind: "na",
        conflictsWithSelection: true,
      }),
    ]);
  });

  it("keeps WAN-conflicting selections for conflict rendering", () => {
    expect(
      shouldResetStalePlannerSelection({
        selectedStatus: "wan_reserved",
        stateReason: undefined,
      }),
    ).toBe(false);
    expect(plannerSelectionIsConflict("wan_reserved")).toBe(true);
  });

  it.each([
    ["ra", "R"],
    ["na", "N"],
    ["pd", "P"],
  ] as const)("shows %s on a selected WAN-conflicting unit", (kind, label) => {
    const wanUnit: PlannerUnit = {
      index: 0,
      kind: "wan",
      selected: true,
      occupiedByRa: false,
      occupiedByNa: false,
      occupiedByPd: false,
      occupiedByOtherLan: false,
      isWanReserved: true,
      isAlignmentBlocked: false,
    };

    expect(plannerUnitLabels(wanUnit, kind)).toBe(label);
  });

  it("keeps an unselected WAN unit unlabeled", () => {
    const wanUnit: PlannerUnit = {
      index: 0,
      kind: "wan",
      selected: false,
      occupiedByRa: false,
      occupiedByNa: false,
      occupiedByPd: false,
      occupiedByOtherLan: false,
      isWanReserved: true,
      isAlignmentBlocked: false,
    };

    expect(plannerUnitLabels(wanUnit, "ra")).toBe("");
  });

  it.each(["selection_out_of_range", "target_shorter_than_parent"] as const)(
    "still resets an unrecoverable %s selection",
    (stateReason) => {
      expect(
        shouldResetStalePlannerSelection({
          selectedStatus: "conflict",
          stateReason,
        }),
      ).toBe(true);
    },
  );
});
