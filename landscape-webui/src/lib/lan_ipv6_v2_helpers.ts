import type { PrefixParentSource } from "@landscape-router/types/api/schemas";

export type SourceType = "static" | "pd";
export type SourceKind = "ra" | "na" | "pd";
export type LanSnapshotCompatibility =
  "unavailable" | "matched" | "compatible" | "insufficient";

export function wanPrefixMeetsExpectation(
  actualPrefixLen: number | null | undefined,
  expectedPrefixLen: number | undefined,
): boolean | undefined {
  if (actualPrefixLen == null || expectedPrefixLen === undefined) {
    return undefined;
  }
  return actualPrefixLen <= expectedPrefixLen;
}

export function lanSnapshotCompatibility(
  expectedPrefixLen: number | undefined,
  snapshotPrefixLen: number,
): LanSnapshotCompatibility {
  if (expectedPrefixLen === undefined) {
    return "unavailable";
  }
  if (expectedPrefixLen === snapshotPrefixLen) {
    return "matched";
  }
  return expectedPrefixLen < snapshotPrefixLen ? "compatible" : "insufficient";
}

export function pdRuntimeReady(
  actualPrefixLen: number | null | undefined,
  expectedPrefixLen: number | undefined,
  snapshotPrefixLen: number,
): boolean {
  return (
    wanPrefixMeetsExpectation(actualPrefixLen, expectedPrefixLen) === true &&
    lanSnapshotCompatibility(expectedPrefixLen, snapshotPrefixLen) !==
      "insufficient" &&
    expectedPrefixLen !== undefined
  );
}

export function sourceTypeFromParent(parent: PrefixParentSource): SourceType {
  return parent.t === "static" ? "static" : "pd";
}

export function groupParentLabel(parent: PrefixParentSource) {
  if (parent.t === "static") {
    return `${parent.base_prefix}/${parent.parent_prefix_len}`;
  }
  return parent.depend_iface;
}
