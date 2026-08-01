import type {
  IPv6ServiceMode,
  LanIPv6ServiceConfigV2,
  LanPrefixGroupConfig,
} from "@landscape-router/types/api/schemas";
import type { LDIAPrefix } from "@/api/service_ipv6pd";
import {
  lanSnapshotCompatibility,
  pdRuntimeReady,
  wanPrefixMeetsExpectation,
  type LanSnapshotCompatibility,
  type SourceKind,
} from "@/lib/lan_ipv6_v2_helpers";

export type PlannerState = "idle" | "preview" | "resolved";
export type PlannerRenderMode = "full" | "summary_only";
export type PlannerSelectionStatus =
  "idle" | "available" | "shared" | "wan_reserved" | "conflict";

export type PlannerCellKind =
  | "available"
  | "wan"
  | "blocked"
  | "ra"
  | "na"
  | "pd"
  | "other_lan"
  | "conflict";

type ServiceKind = "ra" | "na" | "pd";

export interface PlannerOccupant {
  ifaceName: string;
  scope: "current" | "other";
  groupId: string;
  serviceKind: ServiceKind;
  effectiveIndex: number;
  effectiveEndIndex: number;
  poolLen: number;
  conflictsWithSelection: boolean;
}

export interface PlannerUnit {
  index: number;
  kind: PlannerCellKind;
  selected: boolean;
  /** Group occupying this unit on the current LAN, when unambiguous. */
  currentGroupId?: string;
  occupiedByRa: boolean;
  occupiedByNa: boolean;
  occupiedByPd: boolean;
  occupiedByOtherLan: boolean;
  isWanReserved: boolean;
  isAlignmentBlocked: boolean;
  prefix?: string;
}

export interface PlannerView {
  state: PlannerState;
  stateReason?:
    | "no_parent_iface"
    | "missing_pd_config"
    | "no_static_prefix"
    | "target_shorter_than_parent"
    | "selection_out_of_range"
    | "target_more_specific_than_64"
    | "too_many_units";
  dependIface?: string;
  targetPrefixLen?: number;
  parentPrefixLen?: number;
  actualPrefix?: string;
  actualPrefixLen?: number;
  wanCompatible?: boolean;
  lanCompatibility?: LanSnapshotCompatibility;
  runtimeReady: boolean;
  renderMode: PlannerRenderMode;
  totalUnits: number;
  units: PlannerUnit[];
  selectedPoolIndex?: number;
  selectedEffectiveIndex?: number;
  selectedUnitStart?: number;
  selectedUnitSpan?: number;
  selectedPrefix?: string;
  selectedOccupants: PlannerOccupant[];
  selectedStatus: PlannerSelectionStatus;
  canSave: boolean;
  saveError?: string;
}

export function plannerSelectionIsConflict(status: PlannerSelectionStatus) {
  return status === "conflict" || status === "wan_reserved";
}

export function plannerUnitLabels(unit: PlannerUnit, selectedKind: SourceKind) {
  if (unit.isWanReserved && !unit.selected) {
    return "";
  }
  const labels = new Set<string>();
  if (unit.occupiedByRa) {
    labels.add("R");
  }
  if (unit.occupiedByNa) {
    labels.add("N");
  }
  if (unit.occupiedByPd) {
    labels.add("P");
  }
  if (unit.selected) {
    if (selectedKind === "ra") {
      labels.add("R");
    }
    if (selectedKind === "na") {
      labels.add("N");
    }
    if (selectedKind === "pd") {
      labels.add("P");
    }
  }
  return Array.from(labels).join("");
}

export function shouldResetStalePlannerSelection(
  view: Pick<PlannerView, "stateReason" | "selectedStatus">,
) {
  return (
    view.stateReason === "selection_out_of_range" ||
    view.stateReason === "target_shorter_than_parent"
  );
}

export interface BuildGroupPlannerOptions {
  currentIfaceName: string;
  currentGroups: LanPrefixGroupConfig[];
  currentMode?: IPv6ServiceMode;
  otherConfigsV2: LanIPv6ServiceConfigV2[];
  editGroup?: LanPrefixGroupConfig;
  selectedKind: SourceKind;
  prefixInfos: Map<string, LDIAPrefix | null>;
  expectedPdLens?: Map<string, number>;
  draftPdPoolLen?: number;
  maxRenderableUnits?: number;
}

interface LanOccupancyRecord {
  source: "lan";
  ifaceName: string;
  scope: "current" | "other";
  groupId: string;
  serviceKind: ServiceKind;
  effectiveIndex: number;
  effectiveEndIndex: number;
  poolLen: number;
  unitStart?: number;
  unitSpan?: number;
}

interface WanOccupancyRecord {
  source: "wan";
  unitStart: 0;
  unitSpan: 1;
}

type OccupancyRecord = LanOccupancyRecord | WanOccupancyRecord;

const WAN_OCCUPANCY: WanOccupancyRecord = {
  source: "wan",
  unitStart: 0,
  unitSpan: 1,
};

type GroupPlannerParent =
  | {
      t: "static";
      key: string;
      basePrefix: string;
      parentPrefixLen: number;
    }
  | {
      t: "pd";
      key: string;
      dependIface: string;
      snapshotPrefixLen: number;
    };

interface GroupPlannerEntry {
  groupId: string;
  parent: GroupPlannerParent;
  serviceKind: ServiceKind;
  hasSelection: boolean;
  startIndex: number;
  endIndex: number;
  poolLen: number;
}

interface GroupPlannerBaseResult {
  entry: GroupPlannerEntry;
  hasSelection: boolean;
  selectedKind: ServiceKind;
  parentKey: string;
  parentPrefixLen: number;
  targetPrefixLen: number;
  selectedPoolIndex?: number;
  selectedEffectiveIndex?: number;
  selectedUnitStart: number;
  selectedUnitSpan: number;
  actualPrefix?: string;
  actualPrefixLen?: number;
  wanCompatible?: boolean;
  lanCompatibility?: LanSnapshotCompatibility;
  runtimeReady: boolean;
  parentBasePrefix?: string;
  state: PlannerState;
  stateReason?: PlannerView["stateReason"];
  dependIface?: string;
  saveError?: string;
}

export function plannerUnitSpanForPrefix(
  prefixLen: number,
): number | undefined {
  if (!Number.isInteger(prefixLen) || prefixLen <= 0 || prefixLen > 64) {
    return undefined;
  }
  return Number(1n << BigInt(64 - prefixLen));
}

export function alignPlannerUnitRangeToPrefix(
  coveredUnitStart: number,
  coveredUnitEnd: number,
  targetPrefixLen: number,
) {
  const unitSpan = plannerUnitSpanForPrefix(targetPrefixLen);
  if (
    !unitSpan ||
    !Number.isInteger(coveredUnitStart) ||
    !Number.isInteger(coveredUnitEnd) ||
    coveredUnitStart < 0 ||
    coveredUnitEnd <= coveredUnitStart
  ) {
    return undefined;
  }

  return {
    unitStart: Math.floor(coveredUnitStart / unitSpan) * unitSpan,
    unitEnd: Math.ceil(coveredUnitEnd / unitSpan) * unitSpan,
  };
}

function rangesOverlap(
  startA: number,
  spanA: number,
  startB: number,
  spanB: number,
) {
  const endA = startA + spanA;
  const endB = startB + spanB;
  return startA < endB && startB < endA;
}

function conflictBetweenSelection(
  selectedKind: ServiceKind,
  selectedGroupId: string,
  occupantGroupId: string,
  occupantScope: "current" | "other",
  occupantKind: ServiceKind,
) {
  const canShareWithinSameGroup =
    occupantScope === "current" &&
    selectedGroupId === occupantGroupId &&
    ((selectedKind === "ra" && occupantKind === "na") ||
      (selectedKind === "na" && occupantKind === "ra"));

  return !canShareWithinSameGroup;
}

function isLanOccupancyRecord(
  record: OccupancyRecord,
): record is LanOccupancyRecord {
  return record.source === "lan";
}

function ipv6ToBigInt(ip: string): bigint {
  const [headRaw, tailRaw] = ip.toLowerCase().split("::");
  const head = headRaw ? headRaw.split(":").filter(Boolean) : [];
  const tail = tailRaw ? tailRaw.split(":").filter(Boolean) : [];
  const fill = 8 - (head.length + tail.length);
  const groups = [
    ...head,
    ...Array.from({ length: Math.max(fill, 0) }, () => "0"),
    ...tail,
  ];
  if (groups.length !== 8) {
    throw new Error(`Invalid IPv6 address: ${ip}`);
  }
  return groups.reduce(
    (acc, group) => (acc << 16n) + BigInt(parseInt(group || "0", 16)),
    0n,
  );
}

function bigIntToIpv6(value: bigint): string {
  const groups: string[] = [];
  let current = value;
  for (let index = 0; index < 8; index++) {
    groups.unshift((current & 0xffffn).toString(16));
    current >>= 16n;
  }

  let bestStart = -1;
  let bestLen = 0;
  let runStart = -1;
  let runLen = 0;

  groups.forEach((group, index) => {
    if (group === "0") {
      if (runStart === -1) {
        runStart = index;
        runLen = 1;
      } else {
        runLen += 1;
      }
      if (runLen > bestLen) {
        bestStart = runStart;
        bestLen = runLen;
      }
      return;
    }
    runStart = -1;
    runLen = 0;
  });

  if (bestLen < 2) {
    return groups.join(":");
  }

  const left = groups.slice(0, bestStart).join(":");
  const right = groups.slice(bestStart + bestLen).join(":");
  if (!left && !right) {
    return "::";
  }
  if (!left) {
    return `::${right}`;
  }
  if (!right) {
    return `${left}::`;
  }
  return `${left}::${right}`;
}

function maskForPrefix(prefixLen: number): bigint {
  if (prefixLen <= 0) {
    return 0n;
  }
  if (prefixLen >= 128) {
    return (1n << 128n) - 1n;
  }
  const all = (1n << 128n) - 1n;
  return all ^ ((1n << BigInt(128 - prefixLen)) - 1n);
}

function prefixAtIndex(
  basePrefix: string,
  parentPrefixLen: number,
  targetPrefixLen: number,
  index: number,
): string {
  const base = ipv6ToBigInt(basePrefix) & maskForPrefix(parentPrefixLen);
  const shift = BigInt(128 - targetPrefixLen);
  const value = base | (BigInt(index) << shift);
  const network = value & maskForPrefix(targetPrefixLen);
  return `${bigIntToIpv6(network)}/${targetPrefixLen}`;
}

function normalizePrefix(basePrefix: string, prefixLen: number): string {
  const base = ipv6ToBigInt(basePrefix) & maskForPrefix(prefixLen);
  return bigIntToIpv6(base);
}

function selectionStatus(
  selectedKind: ServiceKind,
  selectedGroupId: string,
  records: OccupancyRecord[],
  selectedUnitStart: number,
  selectedUnitSpan: number,
): Pick<
  PlannerView,
  "selectedStatus" | "selectedOccupants" | "canSave" | "saveError"
> {
  const overlappingRecords = records.filter(
    (record) =>
      record.unitStart !== undefined &&
      record.unitSpan !== undefined &&
      rangesOverlap(
        selectedUnitStart,
        selectedUnitSpan,
        record.unitStart,
        record.unitSpan,
      ),
  );
  const selectedOccupants = overlappingRecords
    .filter(isLanOccupancyRecord)
    .map((record) => ({
      ifaceName: record.ifaceName,
      scope: record.scope,
      groupId: record.groupId,
      serviceKind: record.serviceKind,
      effectiveIndex: record.effectiveIndex,
      effectiveEndIndex: record.effectiveEndIndex,
      poolLen: record.poolLen,
      conflictsWithSelection: conflictBetweenSelection(
        selectedKind,
        selectedGroupId,
        record.groupId,
        record.scope,
        record.serviceKind,
      ),
    }));

  if (overlappingRecords.some((record) => record.source === "wan")) {
    return {
      selectedStatus: "wan_reserved",
      selectedOccupants,
      canSave: false,
      saveError: "lan_ipv6.planner_save_error_wan_reserved",
    };
  }

  const hasConflict = selectedOccupants.some(
    (item) => item.conflictsWithSelection,
  );
  if (hasConflict) {
    return {
      selectedStatus: "conflict",
      selectedOccupants,
      canSave: false,
      saveError: "lan_ipv6.planner_save_error_conflict",
    };
  }

  if (selectedOccupants.length > 0) {
    return {
      selectedStatus: "shared",
      selectedOccupants,
      canSave: true,
    };
  }

  return {
    selectedStatus: "available",
    selectedOccupants,
    canSave: true,
  };
}

function recordsConflict(records: LanOccupancyRecord[]): boolean {
  for (let left = 0; left < records.length; left++) {
    for (let right = left + 1; right < records.length; right++) {
      const leftRecord = records[left];
      const rightRecord = records[right];
      if (
        conflictBetweenSelection(
          leftRecord.serviceKind,
          leftRecord.groupId,
          rightRecord.groupId,
          rightRecord.scope,
          rightRecord.serviceKind,
        )
      ) {
        return true;
      }
    }
  }
  return false;
}

function unitKind(
  recordsForUnit: LanOccupancyRecord[],
  occupiedByRa: boolean,
  occupiedByNa: boolean,
  occupiedByPd: boolean,
  occupiedByOtherLan: boolean,
  isWanReserved: boolean,
  isAlignmentBlocked: boolean,
): PlannerCellKind {
  if (isWanReserved) {
    return "wan";
  }
  if (recordsConflict(recordsForUnit)) {
    return "conflict";
  }
  if (occupiedByOtherLan) {
    return "other_lan";
  }
  if (occupiedByPd) {
    return "pd";
  }
  if (occupiedByRa) {
    return "ra";
  }
  if (occupiedByNa) {
    return "na";
  }
  if (isAlignmentBlocked) {
    return "blocked";
  }
  return "available";
}

function idleView(
  stateReason: PlannerView["stateReason"],
  saveError?: string,
): PlannerView {
  return {
    state: "idle",
    stateReason,
    runtimeReady: false,
    renderMode: "summary_only",
    totalUnits: 0,
    units: [],
    selectedOccupants: [],
    selectedStatus: "idle",
    canSave: false,
    saveError,
  };
}

function entryFitsParent(
  entry: GroupPlannerEntry,
  parentPrefixLen: number,
): boolean {
  if (!entry.hasSelection || entry.poolLen <= parentPrefixLen) {
    return !entry.hasSelection;
  }
  if (
    !Number.isInteger(entry.startIndex) ||
    !Number.isInteger(entry.endIndex) ||
    entry.startIndex < 0 ||
    entry.endIndex < entry.startIndex
  ) {
    return false;
  }
  const maxBlocks = 1n << BigInt(entry.poolLen - parentPrefixLen);
  return BigInt(entry.endIndex) < maxBlocks;
}

function runtimeFields(
  base: GroupPlannerBaseResult,
): Pick<PlannerView, "wanCompatible" | "lanCompatibility" | "runtimeReady"> {
  return {
    wanCompatible: base.wanCompatible,
    lanCompatibility: base.lanCompatibility,
    runtimeReady: base.runtimeReady,
  };
}

export function poolIndexFromPlannerUnitStart(
  targetPrefixLen: number,
  unitStart: number,
): number {
  const unitSpan = plannerUnitSpanForPrefix(targetPrefixLen);
  if (!unitSpan) {
    throw new RangeError(
      `Unsupported planner prefix length: ${targetPrefixLen}`,
    );
  }
  return Math.floor(unitStart / unitSpan);
}

function plannerParentFromGroup(
  group: LanPrefixGroupConfig,
): GroupPlannerParent {
  if (group.parent.t === "static") {
    return {
      t: "static",
      key: `static:${group.parent.base_prefix}/${group.parent.parent_prefix_len}`,
      basePrefix: group.parent.base_prefix,
      parentPrefixLen: group.parent.parent_prefix_len,
    };
  }

  return {
    t: "pd",
    key: `pd:${group.parent.depend_iface}/${group.parent.expected_pd_len_snapshot}`,
    dependIface: group.parent.depend_iface,
    snapshotPrefixLen: group.parent.expected_pd_len_snapshot,
  };
}

function occupancyParentKeyForParent(
  parent: GroupPlannerParent,
  prefixInfos: Map<string, LDIAPrefix | null>,
): string {
  if (parent.t === "static") {
    return parent.key;
  }

  const actualPrefix = prefixInfos.get(parent.dependIface) ?? null;
  if (actualPrefix) {
    const actualNetwork = normalizePrefix(
      actualPrefix.prefix_ip,
      actualPrefix.prefix_len,
    );
    return `pd-actual:${normalizePrefix(actualNetwork, parent.snapshotPrefixLen)}/${parent.snapshotPrefixLen}`;
  }

  return parent.key;
}

function entryActiveInMode(
  mode: IPv6ServiceMode | undefined,
  serviceKind: ServiceKind,
): boolean {
  switch (mode) {
    case "slaac":
      return serviceKind === "ra";
    case "stateful":
      return serviceKind === "na" || serviceKind === "pd";
    case "slaac_dhcpv6":
      return true;
    case undefined:
      return true;
    default:
      return true;
  }
}

function buildEntriesForGroup(
  group: LanPrefixGroupConfig,
  mode: IPv6ServiceMode | undefined,
): GroupPlannerEntry[] {
  const parent = plannerParentFromGroup(group);
  const result: GroupPlannerEntry[] = [];

  if (group.ra && entryActiveInMode(mode, "ra")) {
    result.push({
      groupId: group.group_id,
      parent,
      serviceKind: "ra",
      hasSelection: true,
      startIndex: group.ra.pool_index,
      endIndex: group.ra.pool_index,
      poolLen: 64,
    });
  }

  if (group.na && entryActiveInMode(mode, "na")) {
    result.push({
      groupId: group.group_id,
      parent,
      serviceKind: "na",
      hasSelection: true,
      startIndex: group.na.pool_index,
      endIndex: group.na.pool_index,
      poolLen: 64,
    });
  }

  if (group.pd && entryActiveInMode(mode, "pd")) {
    result.push({
      groupId: group.group_id,
      parent,
      serviceKind: "pd",
      hasSelection: true,
      startIndex: group.pd.start_index,
      endIndex: group.pd.end_index,
      poolLen: group.pd.pool_len,
    });
  }

  return result;
}

function defaultEntryForKind(
  group: LanPrefixGroupConfig | undefined,
  kind: SourceKind,
): GroupPlannerEntry | undefined {
  if (!group) {
    return undefined;
  }

  const parent = plannerParentFromGroup(group);
  if (kind === "ra") {
    return {
      groupId: group.group_id,
      parent,
      serviceKind: "ra",
      hasSelection: !!group.ra,
      startIndex: group.ra?.pool_index ?? 0,
      endIndex: group.ra?.pool_index ?? 0,
      poolLen: 64,
    };
  }

  if (kind === "na") {
    return {
      groupId: group.group_id,
      parent,
      serviceKind: "na",
      hasSelection: !!group.na,
      startIndex: group.na?.pool_index ?? 0,
      endIndex: group.na?.pool_index ?? 0,
      poolLen: 64,
    };
  }

  return {
    groupId: group.group_id,
    parent,
    serviceKind: "pd",
    hasSelection: !!group.pd,
    startIndex: group.pd?.start_index ?? 0,
    endIndex: group.pd?.end_index ?? 0,
    poolLen: group.pd?.pool_len ?? 64,
  };
}

function selectedEntryForOptions(
  options: BuildGroupPlannerOptions,
): GroupPlannerEntry | undefined {
  const entry = defaultEntryForKind(options.editGroup, options.selectedKind);
  if (!entry) {
    return undefined;
  }
  if (
    options.selectedKind === "pd" &&
    !options.editGroup?.pd &&
    options.draftPdPoolLen
  ) {
    return {
      ...entry,
      poolLen: options.draftPdPoolLen,
    };
  }
  return entry;
}

function withPoolIndex(
  entry: GroupPlannerEntry,
  poolIndex: number,
): GroupPlannerEntry {
  return {
    ...entry,
    hasSelection: true,
    startIndex: poolIndex,
    endIndex: poolIndex,
  };
}

function entryEffectiveIndexRange(entry: GroupPlannerEntry) {
  return {
    startIndex: entry.startIndex,
    endIndex: entry.endIndex,
  };
}

function entryUnitRange(entry: GroupPlannerEntry) {
  if (
    entry.poolLen <= 0 ||
    entry.poolLen > 64 ||
    !Number.isInteger(entry.startIndex) ||
    !Number.isInteger(entry.endIndex) ||
    entry.startIndex < 0 ||
    entry.endIndex < entry.startIndex
  ) {
    return { unitStart: undefined, unitSpan: undefined };
  }

  const blockSpan = 1n << BigInt(64 - entry.poolLen);
  const unitStart = BigInt(entry.startIndex) * blockSpan;
  const unitSpan = BigInt(entry.endIndex - entry.startIndex + 1) * blockSpan;
  const maxSafe = BigInt(Number.MAX_SAFE_INTEGER);
  if (
    unitStart > maxSafe ||
    unitSpan > maxSafe ||
    unitStart + unitSpan > maxSafe
  ) {
    return { unitStart: undefined, unitSpan: undefined };
  }
  return { unitStart: Number(unitStart), unitSpan: Number(unitSpan) };
}

function buildGroupOccupancyRecord(
  ifaceName: string,
  scope: "current" | "other",
  entry: GroupPlannerEntry,
): LanOccupancyRecord {
  const { unitStart, unitSpan } = entryUnitRange(entry);
  const { startIndex } = entryEffectiveIndexRange(entry);
  return {
    source: "lan",
    ifaceName,
    scope,
    groupId: entry.groupId,
    serviceKind: entry.serviceKind,
    effectiveIndex: startIndex,
    effectiveEndIndex: entry.endIndex,
    poolLen: entry.poolLen,
    unitStart,
    unitSpan,
  };
}

function buildGroupOccupancyRecords(
  options: BuildGroupPlannerOptions,
): OccupancyRecord[] {
  const currentRecords = options.currentGroups.flatMap((group) =>
    // Show all configured results for the current interface on the shared canvas,
    // even if the current service mode would not activate them right now.
    buildEntriesForGroup(group, undefined)
      .filter(
        (entry) =>
          !(
            group === options.editGroup &&
            entry.serviceKind === options.selectedKind
          ),
      )
      .map((entry) =>
        buildGroupOccupancyRecord(options.currentIfaceName, "current", entry),
      ),
  );

  const otherRecords = options.otherConfigsV2.flatMap((config) =>
    (config.config.prefix_groups ?? [])
      // Match the current-interface canvas behavior: keep configured results visible
      // for other LANs as well, so users can see occupied positions even when a mode
      // would not currently activate that kind.
      .flatMap((group) => buildEntriesForGroup(group, undefined))
      .map((entry) =>
        buildGroupOccupancyRecord(config.iface_name, "other", entry),
      ),
  );

  return [WAN_OCCUPANCY, ...currentRecords, ...otherRecords];
}

function buildGroupPlannerViewBase(
  options: BuildGroupPlannerOptions,
  selectedEntry: GroupPlannerEntry | undefined,
): GroupPlannerBaseResult | null {
  if (!selectedEntry) {
    return null;
  }

  const targetPrefixLen = selectedEntry.poolLen;
  const selectedUnitBlock = plannerUnitSpanForPrefix(targetPrefixLen);
  const parentPrefixLen =
    selectedEntry.parent.t === "static"
      ? selectedEntry.parent.parentPrefixLen
      : selectedEntry.parent.snapshotPrefixLen;
  const selectionOutOfRange =
    selectedEntry.hasSelection &&
    targetPrefixLen > parentPrefixLen &&
    !entryFitsParent(selectedEntry, parentPrefixLen);

  if (selectedUnitBlock === undefined) {
    return {
      entry: selectedEntry,
      hasSelection: selectedEntry.hasSelection,
      selectedKind: selectedEntry.serviceKind,
      parentKey: selectedEntry.parent.key,
      parentPrefixLen,
      targetPrefixLen,
      selectedPoolIndex: selectedEntry.hasSelection
        ? selectedEntry.startIndex
        : undefined,
      selectedEffectiveIndex: selectedEntry.hasSelection
        ? entryEffectiveIndexRange(selectedEntry).startIndex
        : undefined,
      selectedUnitStart: 0,
      selectedUnitSpan: 0,
      runtimeReady: false,
      state: "preview",
      stateReason: "target_more_specific_than_64",
      saveError: "lan_ipv6.planner_save_error_target_more_specific_than_64",
    };
  }

  const effectiveRange = entryEffectiveIndexRange(selectedEntry);
  const selectedUnitStart = selectedEntry.hasSelection
    ? effectiveRange.startIndex * selectedUnitBlock
    : 0;
  const selectedUnitSpan = selectedEntry.hasSelection
    ? (effectiveRange.endIndex - effectiveRange.startIndex + 1) *
      selectedUnitBlock
    : 0;

  if (selectedEntry.parent.t === "static") {
    return {
      entry: selectedEntry,
      hasSelection: selectedEntry.hasSelection,
      selectedKind: selectedEntry.serviceKind,
      parentKey: selectedEntry.parent.key,
      parentPrefixLen: selectedEntry.parent.parentPrefixLen,
      targetPrefixLen,
      selectedPoolIndex: selectedEntry.hasSelection
        ? selectedEntry.startIndex
        : undefined,
      selectedEffectiveIndex: selectedEntry.hasSelection
        ? effectiveRange.startIndex
        : undefined,
      selectedUnitStart,
      selectedUnitSpan,
      runtimeReady: true,
      actualPrefix: `${selectedEntry.parent.basePrefix}/${selectedEntry.parent.parentPrefixLen}`,
      actualPrefixLen: selectedEntry.parent.parentPrefixLen,
      parentBasePrefix: selectedEntry.parent.basePrefix,
      state: "resolved",
      stateReason: selectionOutOfRange ? "selection_out_of_range" : undefined,
      saveError: selectionOutOfRange
        ? "lan_ipv6.planner_save_error_selection_out_of_range"
        : undefined,
    };
  }

  if (!selectedEntry.parent.dependIface) {
    return {
      entry: selectedEntry,
      hasSelection: selectedEntry.hasSelection,
      selectedKind: selectedEntry.serviceKind,
      parentKey: "",
      parentPrefixLen: 0,
      targetPrefixLen,
      selectedPoolIndex: selectedEntry.hasSelection
        ? selectedEntry.startIndex
        : undefined,
      selectedEffectiveIndex: selectedEntry.hasSelection
        ? effectiveRange.startIndex
        : undefined,
      selectedUnitStart: 0,
      selectedUnitSpan,
      runtimeReady: false,
      state: "idle",
      stateReason: "no_parent_iface",
      saveError: "lan_ipv6.planner_save_error_no_parent_iface",
    };
  }

  const actualPrefix =
    options.prefixInfos.get(selectedEntry.parent.dependIface) ?? null;
  const snapshotPrefixLen = selectedEntry.parent.snapshotPrefixLen;
  const expectedPrefixLen = options.expectedPdLens?.get(
    selectedEntry.parent.dependIface,
  );
  const wanCompatible = wanPrefixMeetsExpectation(
    actualPrefix?.prefix_len,
    expectedPrefixLen,
  );
  const snapshotCompatibility = lanSnapshotCompatibility(
    expectedPrefixLen,
    snapshotPrefixLen,
  );
  const occupancyParentKey = occupancyParentKeyForParent(
    selectedEntry.parent,
    options.prefixInfos,
  );
  const missingPdConfig =
    options.expectedPdLens !== undefined && expectedPrefixLen === undefined;

  return {
    entry: selectedEntry,
    hasSelection: selectedEntry.hasSelection,
    selectedKind: selectedEntry.serviceKind,
    parentKey: occupancyParentKey,
    parentPrefixLen: snapshotPrefixLen,
    targetPrefixLen,
    selectedPoolIndex: selectedEntry.hasSelection
      ? selectedEntry.startIndex
      : undefined,
    selectedEffectiveIndex: selectedEntry.hasSelection
      ? effectiveRange.startIndex
      : undefined,
    selectedUnitStart,
    selectedUnitSpan,
    actualPrefix: actualPrefix
      ? `${actualPrefix.prefix_ip}/${actualPrefix.prefix_len}`
      : undefined,
    actualPrefixLen: actualPrefix?.prefix_len,
    wanCompatible,
    lanCompatibility: snapshotCompatibility,
    runtimeReady: pdRuntimeReady(
      actualPrefix?.prefix_len,
      expectedPrefixLen,
      snapshotPrefixLen,
    ),
    parentBasePrefix: actualPrefix
      ? normalizePrefix(
          normalizePrefix(actualPrefix.prefix_ip, actualPrefix.prefix_len),
          snapshotPrefixLen,
        )
      : undefined,
    state: actualPrefix ? "resolved" : "preview",
    stateReason: missingPdConfig
      ? "missing_pd_config"
      : selectionOutOfRange
        ? "selection_out_of_range"
        : undefined,
    saveError: missingPdConfig
      ? "lan_ipv6.planner_save_error_missing_pd_config"
      : selectionOutOfRange
        ? "lan_ipv6.planner_save_error_selection_out_of_range"
        : undefined,
    dependIface: selectedEntry.parent.dependIface,
  };
}

function buildGroupPlannerView(
  options: BuildGroupPlannerOptions,
  selectedEntry: GroupPlannerEntry | undefined,
): PlannerView {
  const base = buildGroupPlannerViewBase(options, selectedEntry);
  if (!base) {
    return idleView("no_parent_iface");
  }

  if (!base.parentKey) {
    return idleView(base.stateReason, base.saveError);
  }

  const selectedPrefix =
    base.hasSelection &&
    base.parentBasePrefix &&
    base.targetPrefixLen >= base.parentPrefixLen
      ? prefixAtIndex(
          base.parentBasePrefix,
          base.parentPrefixLen,
          base.targetPrefixLen,
          base.selectedEffectiveIndex!,
        )
      : undefined;

  const allRecords = buildGroupOccupancyRecords(options);

  if (base.saveError) {
    return {
      ...runtimeFields(base),
      state: base.state,
      stateReason: base.stateReason,
      dependIface: base.dependIface,
      targetPrefixLen: base.targetPrefixLen,
      parentPrefixLen: base.parentPrefixLen,
      actualPrefix: base.actualPrefix,
      actualPrefixLen: base.actualPrefixLen,
      renderMode: "summary_only",
      totalUnits: 0,
      units: [],
      selectedPoolIndex: base.selectedPoolIndex,
      selectedEffectiveIndex: base.selectedEffectiveIndex,
      selectedUnitStart: base.selectedUnitStart,
      selectedUnitSpan: base.selectedUnitSpan,
      selectedPrefix,
      selectedOccupants: [],
      selectedStatus: "idle",
      canSave: false,
      saveError: base.saveError,
    };
  }

  if (base.targetPrefixLen <= base.parentPrefixLen) {
    return {
      ...runtimeFields(base),
      state: base.actualPrefix ? base.state : "preview",
      stateReason: "target_shorter_than_parent",
      dependIface: base.dependIface,
      targetPrefixLen: base.targetPrefixLen,
      parentPrefixLen: base.parentPrefixLen,
      actualPrefix: base.actualPrefix,
      actualPrefixLen: base.actualPrefixLen,
      renderMode: "summary_only",
      totalUnits: 0,
      units: [],
      selectedPoolIndex: base.selectedPoolIndex,
      selectedEffectiveIndex: base.selectedEffectiveIndex,
      selectedUnitStart: base.selectedUnitStart,
      selectedUnitSpan: base.selectedUnitSpan,
      selectedPrefix,
      selectedOccupants: [],
      selectedStatus: "idle",
      canSave: false,
      saveError: "lan_ipv6.planner_save_error_target_shorter_than_parent",
    };
  }

  const selection = base.hasSelection
    ? selectionStatus(
        base.selectedKind,
        base.entry.groupId,
        allRecords,
        base.selectedUnitStart,
        base.selectedUnitSpan,
      )
    : {
        selectedStatus: "idle" as const,
        selectedOccupants: [],
        canSave: true,
        saveError: undefined,
      };

  if (base.targetPrefixLen > 64 || base.parentPrefixLen > 64) {
    return {
      ...runtimeFields(base),
      state: base.state,
      stateReason: "target_more_specific_than_64",
      dependIface: base.dependIface,
      targetPrefixLen: base.targetPrefixLen,
      parentPrefixLen: base.parentPrefixLen,
      actualPrefix: base.actualPrefix,
      actualPrefixLen: base.actualPrefixLen,
      renderMode: "summary_only",
      totalUnits: 0,
      units: [],
      selectedPoolIndex: base.selectedPoolIndex,
      selectedEffectiveIndex: base.selectedEffectiveIndex,
      selectedUnitStart: base.selectedUnitStart,
      selectedUnitSpan: base.selectedUnitSpan,
      selectedPrefix,
      selectedOccupants: selection.selectedOccupants,
      selectedStatus: selection.selectedStatus,
      canSave: selection.canSave,
      saveError:
        selection.saveError ??
        "lan_ipv6.planner_save_error_target_more_specific_than_64",
    };
  }

  const totalUnitsBig = 1n << BigInt(64 - base.parentPrefixLen);
  const maxRenderableUnits = BigInt(options.maxRenderableUnits ?? 4096);
  if (totalUnitsBig > maxRenderableUnits) {
    return {
      ...runtimeFields(base),
      state: base.state,
      stateReason: "too_many_units",
      dependIface: base.dependIface,
      targetPrefixLen: base.targetPrefixLen,
      parentPrefixLen: base.parentPrefixLen,
      actualPrefix: base.actualPrefix,
      actualPrefixLen: base.actualPrefixLen,
      renderMode: "summary_only",
      totalUnits: Number(maxRenderableUnits),
      units: [],
      selectedPoolIndex: base.selectedPoolIndex,
      selectedEffectiveIndex: base.selectedEffectiveIndex,
      selectedUnitStart: base.selectedUnitStart,
      selectedUnitSpan: base.selectedUnitSpan,
      selectedPrefix,
      selectedOccupants: selection.selectedOccupants,
      selectedStatus: selection.selectedStatus,
      canSave: selection.canSave,
      saveError: selection.saveError,
    };
  }

  const totalUnits = Number(totalUnitsBig);
  const units: PlannerUnit[] = [];
  const candidateUnitSpan = plannerUnitSpanForPrefix(base.targetPrefixLen) ?? 1;
  const blockedBlockStarts = new Set<number>();

  for (
    let blockStart = 0;
    blockStart < totalUnits;
    blockStart += candidateUnitSpan
  ) {
    const blockEnd = Math.min(totalUnits, blockStart + candidateUnitSpan);
    const blockRecords = allRecords.filter(
      (record) =>
        record.unitStart !== undefined &&
        record.unitSpan !== undefined &&
        rangesOverlap(
          blockStart,
          blockEnd - blockStart,
          record.unitStart,
          record.unitSpan,
        ),
    );
    const conflictingRecords = blockRecords.filter(
      (record) =>
        record.source === "wan" ||
        conflictBetweenSelection(
          base.selectedKind,
          base.entry.groupId,
          record.groupId,
          record.scope,
          record.serviceKind,
        ),
    );

    if (conflictingRecords.length > 0) {
      blockedBlockStarts.add(blockStart);
    }
  }

  for (let index = 0; index < totalUnits; index++) {
    const recordsForUnit = allRecords.filter(
      (record) =>
        record.unitStart !== undefined &&
        record.unitSpan !== undefined &&
        index >= record.unitStart &&
        index < record.unitStart + record.unitSpan,
    );
    const lanRecordsForUnit = recordsForUnit.filter(isLanOccupancyRecord);
    const occupiedByRa = lanRecordsForUnit.some(
      (record) => record.serviceKind === "ra",
    );
    const occupiedByNa = lanRecordsForUnit.some(
      (record) => record.serviceKind === "na",
    );
    const occupiedByPd = lanRecordsForUnit.some(
      (record) => record.serviceKind === "pd",
    );
    const occupiedByOtherLan = lanRecordsForUnit.some(
      (record) => record.scope === "other",
    );
    const currentGroupIds = new Set(
      lanRecordsForUnit
        .filter((record) => record.scope === "current")
        .map((record) => record.groupId),
    );
    const currentGroupId =
      currentGroupIds.size === 1
        ? currentGroupIds.values().next().value
        : undefined;
    const isWanReserved = recordsForUnit.some(
      (record) => record.source === "wan",
    );
    const blockStart =
      Math.floor(index / candidateUnitSpan) * candidateUnitSpan;
    const hasOccupancy =
      occupiedByRa || occupiedByNa || occupiedByPd || occupiedByOtherLan;
    const isAlignmentBlocked =
      !isWanReserved && !hasOccupancy && blockedBlockStarts.has(blockStart);
    const selected =
      base.hasSelection &&
      index >= base.selectedUnitStart &&
      index < base.selectedUnitStart + base.selectedUnitSpan;

    units.push({
      index,
      kind: unitKind(
        lanRecordsForUnit,
        occupiedByRa,
        occupiedByNa,
        occupiedByPd,
        occupiedByOtherLan,
        isWanReserved,
        isAlignmentBlocked,
      ),
      selected,
      currentGroupId,
      occupiedByRa,
      occupiedByNa,
      occupiedByPd,
      occupiedByOtherLan,
      isWanReserved,
      isAlignmentBlocked,
      prefix: base.parentBasePrefix
        ? prefixAtIndex(base.parentBasePrefix, base.parentPrefixLen, 64, index)
        : undefined,
    });
  }

  return {
    ...runtimeFields(base),
    state: base.state,
    stateReason: base.stateReason,
    dependIface: base.dependIface,
    targetPrefixLen: base.targetPrefixLen,
    parentPrefixLen: base.parentPrefixLen,
    actualPrefix: base.actualPrefix,
    actualPrefixLen: base.actualPrefixLen,
    renderMode: "full",
    totalUnits,
    units,
    selectedPoolIndex: base.selectedPoolIndex,
    selectedEffectiveIndex: base.selectedEffectiveIndex,
    selectedUnitStart: base.selectedUnitStart,
    selectedUnitSpan: base.selectedUnitSpan,
    selectedPrefix,
    selectedOccupants: selection.selectedOccupants,
    selectedStatus: selection.selectedStatus,
    canSave: selection.canSave,
    saveError: selection.saveError,
  };
}

export function buildPrefixPlannerViewFromGroups(
  options: BuildGroupPlannerOptions,
): PlannerView {
  return buildGroupPlannerView(options, selectedEntryForOptions(options));
}

export function inspectPlannerCandidateFromGroups(
  options: BuildGroupPlannerOptions,
  poolIndex: number,
): Pick<
  PlannerView,
  | "selectedPoolIndex"
  | "selectedEffectiveIndex"
  | "selectedPrefix"
  | "selectedOccupants"
  | "selectedStatus"
  | "canSave"
  | "saveError"
> {
  const selectedEntry = selectedEntryForOptions(options);
  if (!selectedEntry) {
    return {
      selectedOccupants: [],
      selectedStatus: "idle",
      canSave: false,
      saveError: "lan_ipv6.planner_save_error_no_parent_iface",
    };
  }

  const nextView = buildGroupPlannerView(
    options,
    withPoolIndex(selectedEntry, poolIndex),
  );
  return {
    selectedPoolIndex: nextView.selectedPoolIndex,
    selectedEffectiveIndex: nextView.selectedEffectiveIndex,
    selectedPrefix: nextView.selectedPrefix,
    selectedOccupants: nextView.selectedOccupants,
    selectedStatus: nextView.selectedStatus,
    canSave: nextView.canSave,
    saveError: nextView.saveError,
  };
}

export function inspectPlannerUnitRangeCandidateFromGroups(
  options: BuildGroupPlannerOptions,
  unitStart: number,
  unitSpan: number,
): Pick<
  PlannerView,
  | "selectedOccupants"
  | "selectedStatus"
  | "canSave"
  | "saveError"
  | "selectedUnitStart"
  | "selectedUnitSpan"
> {
  const base = buildGroupPlannerViewBase(
    options,
    selectedEntryForOptions(options),
  );
  if (!base) {
    return {
      selectedOccupants: [],
      selectedStatus: "idle",
      canSave: false,
      saveError: "lan_ipv6.planner_save_error_no_parent_iface",
      selectedUnitStart: unitStart,
      selectedUnitSpan: unitSpan,
    };
  }

  const selection = selectionStatus(
    base.selectedKind,
    base.entry.groupId,
    buildGroupOccupancyRecords(options),
    unitStart,
    unitSpan,
  );

  return {
    selectedOccupants: selection.selectedOccupants,
    selectedStatus: selection.selectedStatus,
    canSave: selection.canSave,
    saveError: selection.saveError,
    selectedUnitStart: unitStart,
    selectedUnitSpan: unitSpan,
  };
}
