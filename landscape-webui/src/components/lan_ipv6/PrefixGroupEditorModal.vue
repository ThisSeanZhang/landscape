<script setup lang="ts">
import {
  get_all_ipv6pd_configs,
  get_all_ipv6pd_status,
  get_current_ip_prefix_info,
  type LDIAPrefix,
} from "@/api/service_ipv6pd";
import { get_all_lan_ipv6_configs } from "@/api/service_lan_ipv6";
import PdPrefixPlanner from "@/components/lan_ipv6/PdPrefixPlanner.vue";
import {
  buildPrefixPlannerViewFromGroups,
  inspectPlannerUnitRangeCandidateFromGroups,
  poolIndexFromPlannerUnitStart,
} from "@/lib/ipv6_planner";
import { ServiceStatus } from "@/lib/services";
import type { IPV6PDServiceConfig } from "@/lib/ipv6pd";
import type {
  IPv6ServiceMode,
  LanIPv6ServiceConfigV2,
  LanPrefixGroupConfig,
} from "@landscape-router/types/api/schemas";
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";

const { t } = useI18n({ useScope: "global" });

type ServiceKind = "ra" | "na" | "pd";
type SourceType = "static" | "pd";

interface PlannerInteractionPayload {
  poolIndex: number;
  unitStart: number;
  unitSpan: number;
  canSave: boolean;
  saveError?: string;
  occupants: {
    scope: "current" | "other";
    serviceKind: ServiceKind;
    ifaceName: string;
    groupId: string;
    effectiveIndex: number;
    effectiveEndIndex: number;
    poolLen: number;
    conflictsWithSelection: boolean;
  }[];
}

function randomUint32() {
  if (typeof globalThis.crypto !== "undefined") {
    const buffer = new Uint32Array(1);
    globalThis.crypto.getRandomValues(buffer);
    return buffer[0];
  }
  return Math.floor(Math.random() * 0x1_0000_0000);
}

function generateDefaultStaticBasePrefix() {
  const mixed =
    ((BigInt(Date.now()) << 16n) ^ BigInt(randomUint32())) & 0xffffffffffffn;
  const hex = mixed.toString(16).padStart(12, "0");
  return `fd${hex.slice(0, 2)}:${hex.slice(2, 6)}:${hex.slice(6, 10)}:${hex.slice(10, 12)}00::`;
}

const show = defineModel<boolean>("show", { required: true });

const props = defineProps<{
  sourceType: SourceType;
  parentLabel: string;
  group?: LanPrefixGroupConfig;
  allowedServiceKinds?: ServiceKind[];
  currentIfaceName: string;
  currentGroups?: LanPrefixGroupConfig[];
  currentMode?: IPv6ServiceMode;
  initialKind?: ServiceKind;
}>();

const emit = defineEmits<{
  (e: "commit", value: LanPrefixGroupConfig | undefined): void;
}>();

const switchKinds: ServiceKind[] = ["ra", "na", "pd"];
const selectedKind = ref<ServiceKind>("ra");
const staticBasePrefix = ref(generateDefaultStaticBasePrefix());
const staticPrefixLen = ref(56);
const dependIface = ref("");
const snapshotPrefixLen = ref(60);
const pdPoolLenDraft = ref(64);
const draftGroupId = ref("");

const otherLanConfigsV2 = ref<LanIPv6ServiceConfigV2[]>([]);
const prefixInfos = ref<Map<string, LDIAPrefix | null>>(new Map());
const ipv6PdIfaces = ref<Map<string, ServiceStatus>>(new Map());
const ipv6PdConfigs = ref<IPV6PDServiceConfig[]>([]);
const expectedPdLens = ref<Map<string, number>>(new Map());
const draftGroupState = ref<LanPrefixGroupConfig>();
const staleSelectionsCleared = ref(false);
const emptyDraftActionVisible = ref(false);

const draftGroup = computed(() => draftGroupState.value);

const availableServiceKinds = computed(() => {
  if (props.allowedServiceKinds && props.allowedServiceKinds.length > 0) {
    return props.allowedServiceKinds;
  }
  return ["ra", "na", "pd"] as ServiceKind[];
});

const ipv6PdOptions = computed(() => {
  return ipv6PdConfigs.value.map((config) => {
    const status = ipv6PdIfaces.value.get(config.iface_name);
    const statusLabel = status ? ` - ${status.t}` : "";
    return {
      value: config.iface_name,
      label: `${config.iface_name} /${config.config.expected_pd_len}${statusLabel}`,
    };
  });
});

const currentPlannerGroups = computed(() => {
  const groups = props.currentGroups ?? [];
  const remaining = props.group
    ? groups.filter((group) => group.group_id !== props.group?.group_id)
    : groups;
  return draftGroup.value ? [draftGroup.value, ...remaining] : remaining;
});

const minPdPoolLen = computed(() => {
  if (props.sourceType === "static") {
    return Math.min(staticPrefixLen.value + 1, 64);
  }
  return Math.min(snapshotPrefixLen.value + 1, 64);
});

const currentPdPoolLen = computed(
  () => draftGroup.value?.pd?.pool_len ?? pdPoolLenDraft.value,
);

const displayParentLabel = computed(() => {
  const group = draftGroup.value;
  if (!group) {
    return props.parentLabel;
  }
  if (group.parent.t === "static") {
    return `${group.parent.base_prefix}/${group.parent.parent_prefix_len}`;
  }
  return group.parent.depend_iface || props.parentLabel;
});

const draftGroupHasResults = computed(
  () =>
    !!(draftGroup.value?.ra || draftGroup.value?.na || draftGroup.value?.pd),
);

const commitSaveState = computed(() => {
  if (!draftGroupHasResults.value || !draftGroup.value) {
    return { canSave: true as const, saveError: undefined };
  }

  for (const kind of switchKinds) {
    if (!kindConfigured(kind)) {
      continue;
    }
    const view = buildPrefixPlannerViewFromGroups({
      currentIfaceName: props.currentIfaceName,
      currentGroups: currentPlannerGroups.value,
      currentMode: props.currentMode,
      otherConfigsV2: otherLanConfigsV2.value,
      editGroup: draftGroup.value,
      selectedKind: kind,
      prefixInfos: prefixInfos.value,
      expectedPdLens: expectedPdLens.value,
      draftPdPoolLen: currentPdPoolLen.value,
    });
    if (!view.canSave) {
      return {
        canSave: false as const,
        saveError: view.saveError ?? "lan_ipv6.planner_save_error_conflict",
      };
    }
  }

  return { canSave: true as const, saveError: undefined };
});

function cloneValue<T>(value: T): T {
  return JSON.parse(JSON.stringify(value));
}

function generateDraftGroupId() {
  return `prefix-group:${globalThis.crypto.randomUUID()}`;
}

function createEmptyDraftGroup(): LanPrefixGroupConfig {
  if (props.sourceType === "static") {
    return {
      group_id: draftGroupId.value,
      parent: {
        t: "static",
        base_prefix: staticBasePrefix.value,
        parent_prefix_len: staticPrefixLen.value,
      },
      ra: null,
      na: null,
      pd: null,
    };
  }

  return {
    group_id: draftGroupId.value,
    parent: {
      t: "pd",
      depend_iface: dependIface.value,
      expected_pd_len_snapshot: snapshotPrefixLen.value,
    },
    ra: null,
    na: null,
    pd: null,
  };
}

function ensureDraftGroup() {
  if (!draftGroupState.value) {
    draftGroupState.value = createEmptyDraftGroup();
  }
  return draftGroupState.value;
}

function syncParentIntoDraftGroup() {
  const group = ensureDraftGroup();
  if (props.sourceType === "static") {
    group.parent = {
      t: "static",
      base_prefix: staticBasePrefix.value,
      parent_prefix_len: staticPrefixLen.value,
    };
    return;
  }
  group.parent = {
    t: "pd",
    depend_iface: dependIface.value,
    expected_pd_len_snapshot: snapshotPrefixLen.value,
  };
}

function reservedBlockOffsetForPrefix(targetPrefixLen: number) {
  if (targetPrefixLen <= 64) {
    return 1;
  }
  const shift = targetPrefixLen - 64;
  if (shift >= 31) {
    return Number.MAX_SAFE_INTEGER;
  }
  return 1 << shift;
}

function unitSpanForPrefix(prefixLen: number) {
  if (prefixLen <= 0 || prefixLen > 64) {
    return undefined;
  }
  return Number(1n << BigInt(64 - prefixLen));
}

function kindConfigured(kind: ServiceKind) {
  if (!draftGroup.value) {
    return false;
  }
  if (kind === "ra") {
    return !!draftGroup.value.ra;
  }
  if (kind === "na") {
    return !!draftGroup.value.na;
  }
  return !!draftGroup.value.pd;
}

function kindCount(kind: ServiceKind) {
  if (!draftGroup.value) {
    return 0;
  }
  if (kind === "pd") {
    return draftGroup.value.pd
      ? draftGroup.value.pd.end_index - draftGroup.value.pd.start_index + 1
      : 0;
  }
  return kindConfigured(kind) ? 1 : 0;
}

function canSwitchKind(kind: ServiceKind) {
  return availableServiceKinds.value.includes(kind) || kindConfigured(kind);
}

function selectKind(kind: ServiceKind) {
  if (!canSwitchKind(kind)) {
    return;
  }
  selectedKind.value = kind;
}

function clearKind(kind: ServiceKind) {
  const group = ensureDraftGroup();
  if (kind === "ra") {
    group.ra = null;
    return;
  }
  if (kind === "na") {
    group.na = null;
    return;
  }
  group.pd = null;
}

function poolIndexFromSelectionUnitStart(
  unitStart: number,
  targetPrefixLen: number,
) {
  return poolIndexFromPlannerUnitStart(
    targetPrefixLen,
    reservedBlockOffsetForPrefix(targetPrefixLen),
    unitStart,
  );
}

function rangeForSelection(
  startIndex: number,
  endIndex: number,
  poolLen: number,
) {
  const unitSpan = unitSpanForPrefix(poolLen);
  if (!unitSpan) {
    return undefined;
  }
  const effectiveStart = startIndex;
  const effectiveEnd = endIndex;
  return {
    unitStart: effectiveStart * unitSpan,
    unitEnd: (effectiveEnd + 1) * unitSpan,
    unitSpan,
    poolIndexStart: startIndex,
    poolIndexEnd: endIndex,
    poolLen,
  };
}

function currentPdExtent() {
  const pd = draftGroup.value?.pd;
  if (!pd) {
    return undefined;
  }
  return rangeForSelection(pd.start_index, pd.end_index, pd.pool_len);
}

function intervalFromUnitRange(
  unitStart: number,
  unitEnd: number,
  poolLen: number,
) {
  const unitSpan = unitSpanForPrefix(poolLen);
  if (!unitSpan) {
    return undefined;
  }
  const totalSpan = unitEnd - unitStart;
  if (
    totalSpan <= 0 ||
    unitStart % unitSpan !== 0 ||
    totalSpan % unitSpan !== 0
  ) {
    return undefined;
  }
  const startIndex = poolIndexFromSelectionUnitStart(unitStart, poolLen);
  const endIndex = poolIndexFromSelectionUnitStart(unitEnd - unitSpan, poolLen);
  if (startIndex === undefined || endIndex === undefined) {
    return undefined;
  }
  return { startIndex, endIndex };
}

function intervalFromCoveredUnits(
  coveredUnitStart: number,
  coveredUnitEnd: number,
  poolLen: number,
) {
  const unitSpan = unitSpanForPrefix(poolLen);
  if (!unitSpan) {
    return undefined;
  }
  const baseStart = reservedBlockOffsetForPrefix(poolLen) * unitSpan;
  const alignedStart =
    baseStart +
    Math.max(0, Math.floor((coveredUnitStart - baseStart) / unitSpan)) *
      unitSpan;
  const alignedEnd =
    baseStart +
    Math.max(1, Math.ceil((coveredUnitEnd - baseStart) / unitSpan)) * unitSpan;
  if (alignedEnd <= alignedStart) {
    return undefined;
  }
  return intervalFromUnitRange(alignedStart, alignedEnd, poolLen);
}

function validatePdInterval(
  startIndex: number,
  endIndex: number,
  poolLen: number,
) {
  const nextRange = rangeForSelection(startIndex, endIndex, poolLen);
  if (!nextRange) {
    return {
      canSave: false,
      saveError: "lan_ipv6.planner_save_error_wan_reserved",
    };
  }

  return inspectPlannerUnitRangeCandidateFromGroups(
    {
      currentIfaceName: props.currentIfaceName,
      currentGroups: currentPlannerGroups.value,
      currentMode: props.currentMode,
      otherConfigsV2: otherLanConfigsV2.value,
      editGroup: draftGroup.value,
      selectedKind: "pd",
      prefixInfos: prefixInfos.value,
      expectedPdLens: expectedPdLens.value,
      draftPdPoolLen: poolLen,
    },
    nextRange.unitStart,
    nextRange.unitEnd - nextRange.unitStart,
  );
}

function setRaPoolIndex(poolIndex: number) {
  const group = ensureDraftGroup();
  // RA lifetimes are global (ad_interval-based), no longer stored per-group.
  group.ra = { pool_index: poolIndex };
}

function setNaPoolIndex(poolIndex: number) {
  const group = ensureDraftGroup();
  group.na = { pool_index: poolIndex };
}

function setPdInterval(startIndex: number, endIndex: number, poolLen: number) {
  const group = ensureDraftGroup();
  if (endIndex < startIndex) {
    group.pd = null;
    return;
  }
  group.pd = {
    start_index: startIndex,
    end_index: endIndex,
    pool_len: poolLen,
  };
}

function onDependIfaceChange() {
  snapshotPrefixLen.value = expectedPdLens.value.get(dependIface.value) ?? 60;
  syncParentIntoDraftGroup();
}

function onPlannerInteract(payload: PlannerInteractionPayload) {
  if (selectedKind.value !== "pd") {
    const currentEntry =
      selectedKind.value === "ra" ? draftGroup.value?.ra : draftGroup.value?.na;
    if (currentEntry?.pool_index === payload.poolIndex) {
      clearKind(selectedKind.value);
      return;
    }
    if (!payload.canSave) {
      if (payload.saveError) {
        window.$message.error(t(payload.saveError));
      }
      return;
    }
    if (selectedKind.value === "ra") {
      setRaPoolIndex(payload.poolIndex);
    } else {
      setNaPoolIndex(payload.poolIndex);
    }
    return;
  }

  const poolLen = currentPdPoolLen.value;
  const clickedRange = rangeForSelection(
    payload.poolIndex,
    payload.poolIndex,
    poolLen,
  );
  if (!clickedRange) {
    return;
  }

  const currentPd = draftGroup.value?.pd;
  if (!currentPd) {
    if (!payload.canSave) {
      if (payload.saveError) {
        window.$message.error(t(payload.saveError));
      }
      return;
    }
    setPdInterval(payload.poolIndex, payload.poolIndex, poolLen);
    return;
  }

  const pdExtent = currentPdExtent();
  if (!pdExtent) {
    return;
  }

  if (
    payload.poolIndex >= currentPd.start_index &&
    payload.poolIndex <= currentPd.end_index
  ) {
    if (currentPd.start_index === currentPd.end_index) {
      clearKind("pd");
      return;
    }
    if (payload.poolIndex === currentPd.start_index) {
      setPdInterval(
        currentPd.start_index + 1,
        currentPd.end_index,
        currentPd.pool_len,
      );
      return;
    }
    if (payload.poolIndex === currentPd.end_index) {
      setPdInterval(
        currentPd.start_index,
        currentPd.end_index - 1,
        currentPd.pool_len,
      );
    }
    return;
  }

  if (!payload.canSave) {
    if (payload.saveError) {
      window.$message.error(t(payload.saveError));
    }
    return;
  }

  const adjacentLeft = payload.poolIndex === currentPd.start_index - 1;
  const adjacentRight = payload.poolIndex === currentPd.end_index + 1;
  if (!adjacentLeft && !adjacentRight) {
    window.$message.warning(t("lan_ipv6.pd_must_be_continuous"));
    return;
  }

  const unitStart = Math.min(pdExtent.unitStart, clickedRange.unitStart);
  const unitEnd = Math.max(pdExtent.unitEnd, clickedRange.unitEnd);
  const rangeCandidate = inspectPlannerUnitRangeCandidateFromGroups(
    {
      currentIfaceName: props.currentIfaceName,
      currentGroups: currentPlannerGroups.value,
      currentMode: props.currentMode,
      otherConfigsV2: otherLanConfigsV2.value,
      editGroup: draftGroup.value,
      selectedKind: "pd",
      prefixInfos: prefixInfos.value,
      expectedPdLens: expectedPdLens.value,
      draftPdPoolLen: poolLen,
    },
    unitStart,
    unitEnd - unitStart,
  );
  if (!rangeCandidate.canSave) {
    if (rangeCandidate.saveError) {
      window.$message.error(t(rangeCandidate.saveError));
    }
    return;
  }

  setPdInterval(
    Math.min(currentPd.start_index, payload.poolIndex),
    Math.max(currentPd.end_index, payload.poolIndex),
    currentPd.pool_len,
  );
}

function updatePdPoolLen(value: number | null) {
  if (typeof value !== "number") {
    return;
  }

  const nextPoolLen = Math.max(minPdPoolLen.value, Math.min(value, 64));
  const group = ensureDraftGroup();
  if (!group.pd) {
    pdPoolLenDraft.value = nextPoolLen;
    return;
  }

  const previousPoolLen = group.pd.pool_len;
  const previousExtent = currentPdExtent();
  if (!previousExtent) {
    pdPoolLenDraft.value = previousPoolLen;
    return;
  }

  const nextInterval = intervalFromCoveredUnits(
    previousExtent.unitStart,
    previousExtent.unitEnd,
    nextPoolLen,
  );
  if (!nextInterval) {
    pdPoolLenDraft.value = previousPoolLen;
    window.$message.error(t("lan_ipv6.planner_save_error_wan_reserved"));
    return;
  }

  const nextCandidate = validatePdInterval(
    nextInterval.startIndex,
    nextInterval.endIndex,
    nextPoolLen,
  );
  if (!nextCandidate.canSave) {
    pdPoolLenDraft.value = previousPoolLen;
    if (nextCandidate.saveError) {
      window.$message.error(t(nextCandidate.saveError));
    }
    return;
  }

  pdPoolLenDraft.value = nextPoolLen;
  group.pd.pool_len = nextPoolLen;
  group.pd.start_index = nextInterval.startIndex;
  group.pd.end_index = nextInterval.endIndex;
}

async function searchIpv6Pd() {
  const [statuses, configs] = await Promise.all([
    get_all_ipv6pd_status(),
    get_all_ipv6pd_configs(),
  ]);
  ipv6PdIfaces.value = statuses;
  ipv6PdConfigs.value = configs;
  expectedPdLens.value = new Map(
    configs.map((config) => [config.iface_name, config.config.expected_pd_len]),
  );
}

async function loadPlannerContext() {
  prefixInfos.value = await get_current_ip_prefix_info();
  const allConfigs = await get_all_lan_ipv6_configs();
  otherLanConfigsV2.value = allConfigs.filter(
    (config) => config.iface_name !== props.currentIfaceName,
  );
}

function firstConfiguredKind() {
  if (draftGroup.value?.ra) {
    return "ra" as const;
  }
  if (draftGroup.value?.na) {
    return "na" as const;
  }
  if (draftGroup.value?.pd) {
    return "pd" as const;
  }
  return undefined;
}

function initDraftGroup() {
  draftGroupId.value = props.group?.group_id ?? generateDraftGroupId();
  staleSelectionsCleared.value = false;
  emptyDraftActionVisible.value = false;

  if (props.group) {
    draftGroupState.value = cloneValue(props.group);
    if (props.group.parent.t === "static") {
      staticBasePrefix.value = props.group.parent.base_prefix;
      staticPrefixLen.value = props.group.parent.parent_prefix_len;
    } else {
      dependIface.value = props.group.parent.depend_iface;
      snapshotPrefixLen.value =
        expectedPdLens.value.get(dependIface.value) ??
        props.group.parent.expected_pd_len_snapshot;
    }
    pdPoolLenDraft.value = props.group.pd?.pool_len ?? 64;
    return;
  }

  if (props.sourceType === "static") {
    staticBasePrefix.value = generateDefaultStaticBasePrefix();
    staticPrefixLen.value = 56;
  } else {
    dependIface.value = "";
    snapshotPrefixLen.value = 60;
  }
  pdPoolLenDraft.value = 64;
  draftGroupState.value = createEmptyDraftGroup();
}

function clearStaleSelectionsOnOpen() {
  if (!props.group || !draftGroup.value) {
    return;
  }

  const hasStaleSelection = switchKinds.some((kind) => {
    if (!kindConfigured(kind)) {
      return false;
    }

    const view = buildPrefixPlannerViewFromGroups({
      currentIfaceName: props.currentIfaceName,
      currentGroups: currentPlannerGroups.value,
      currentMode: props.currentMode,
      otherConfigsV2: otherLanConfigsV2.value,
      editGroup: draftGroup.value,
      selectedKind: kind,
      prefixInfos: prefixInfos.value,
      expectedPdLens: expectedPdLens.value,
      draftPdPoolLen: currentPdPoolLen.value,
    });
    return (
      view.stateReason === "selection_out_of_range" ||
      view.stateReason === "target_shorter_than_parent" ||
      view.selectedStatus === "wan_reserved"
    );
  });

  if (!hasStaleSelection) {
    return;
  }

  for (const kind of switchKinds) {
    clearKind(kind);
  }
  pdPoolLenDraft.value = Math.max(pdPoolLenDraft.value, minPdPoolLen.value);
  staleSelectionsCleared.value = true;
}

async function enter() {
  staleSelectionsCleared.value = false;
  emptyDraftActionVisible.value = false;
  await Promise.all([searchIpv6Pd(), loadPlannerContext()]);
  initDraftGroup();
  syncParentIntoDraftGroup();
  clearStaleSelectionsOnOpen();
  const firstKind =
    props.initialKind ??
    firstConfiguredKind() ??
    availableServiceKinds.value[0] ??
    "ra";
  selectKind(firstKind);
}

async function commit() {
  if (draftGroupHasResults.value && !commitSaveState.value.canSave) {
    window.$message.error(
      t(
        commitSaveState.value.saveError ??
          "lan_ipv6.planner_save_error_conflict",
      ),
    );
    return;
  }

  if (
    props.group &&
    staleSelectionsCleared.value &&
    !draftGroupHasResults.value
  ) {
    emptyDraftActionVisible.value = true;
    return;
  }

  const groupToCommit =
    draftGroupHasResults.value && draftGroup.value
      ? cloneValue(draftGroup.value)
      : undefined;

  if (groupToCommit?.parent.t === "pd" && !groupToCommit.parent.depend_iface) {
    window.$message.error(t("lan_ipv6.planner_save_error_no_parent_iface"));
    return;
  }

  if (groupToCommit?.pd) {
    const parentPrefixLen =
      groupToCommit.parent.t === "static"
        ? groupToCommit.parent.parent_prefix_len
        : groupToCommit.parent.expected_pd_len_snapshot;
    if (groupToCommit.pd.pool_len <= parentPrefixLen) {
      window.$message.error(
        `IA_PD /${groupToCommit.pd.pool_len} must be longer than parent /${parentPrefixLen}`,
      );
      return;
    }
  }

  emit("commit", groupToCommit);
  show.value = false;
}

function deleteCurrentGroup() {
  emptyDraftActionVisible.value = false;
  emit("commit", undefined);
  show.value = false;
}

function cancelEmptyDraftAction() {
  emptyDraftActionVisible.value = false;
  show.value = false;
}
</script>

<template>
  <n-modal
    :auto-focus="false"
    style="width: 1180px"
    v-model:show="show"
    preset="card"
    :title="
      t('lan_ipv6.prefix_group_editor_title', { parent: displayParentLabel })
    "
    size="small"
    :bordered="false"
    @after-enter="enter"
  >
    <n-flex vertical :size="12">
      <n-alert v-if="staleSelectionsCleared" type="warning" :bordered="false">
        {{ t("lan_ipv6.stale_selection_reset_notice") }}
      </n-alert>

      <n-card size="small" :bordered="false">
        <n-flex vertical :size="10">
          <n-flex align="center" justify="space-between">
            <div>
              <strong>{{ t("lan_ipv6.prefix_group_editor_parent") }}</strong>
              {{ displayParentLabel }}
            </div>
          </n-flex>

          <n-form-item
            v-if="sourceType === 'static'"
            :label="t('lan_ipv6.source_base_prefix')"
          >
            <n-flex style="flex: 1" :gap="8">
              <n-input
                style="flex: 1"
                v-model:value="staticBasePrefix"
                @update:value="syncParentIntoDraftGroup"
              />
              <n-input-number
                style="width: 120px"
                v-model:value="staticPrefixLen"
                :min="1"
                :max="127"
                @update:value="syncParentIntoDraftGroup"
              />
            </n-flex>
          </n-form-item>
          <n-form-item v-else :label="t('lan_ipv6.source_depend_iface')">
            <n-select
              v-model:value="dependIface"
              filterable
              :options="ipv6PdOptions"
              :placeholder="t('lan_ipv6.source_depend_iface_placeholder')"
              clearable
              remote
              @update:value="onDependIfaceChange"
              @search="searchIpv6Pd"
            />
          </n-form-item>

          <n-grid cols="1 l:3" responsive="screen" :x-gap="12" :y-gap="12">
            <n-gi>
              <n-flex vertical :size="6">
                <n-text depth="3" style="font-size: 12px">
                  {{ t("lan_ipv6.prefix_group_editor_kind") }}
                </n-text>
                <n-grid cols="1" :x-gap="8" :y-gap="8">
                  <n-gi v-for="kind in switchKinds" :key="kind">
                    <div
                      class="kind-switch"
                      :class="{
                        active: selectedKind === kind,
                        disabled: !canSwitchKind(kind),
                      }"
                      @click="selectKind(kind)"
                    >
                      <div class="kind-switch-title">
                        {{ t(`lan_ipv6.planner_brush_${kind}`) }}
                      </div>
                      <div class="kind-switch-count">
                        {{
                          t("lan_ipv6.prefix_group_count", {
                            count: kindCount(kind),
                          })
                        }}
                      </div>
                      <div
                        v-if="kind === 'pd'"
                        class="kind-switch-extra"
                        @click.stop
                      >
                        <n-text depth="3" style="font-size: 12px">
                          {{ t("lan_ipv6.source_pool_len") }}
                        </n-text>
                        <n-input-number
                          :value="currentPdPoolLen"
                          :min="minPdPoolLen"
                          :max="64"
                          size="small"
                          @update:value="updatePdPoolLen"
                        />
                      </div>
                    </div>
                  </n-gi>
                </n-grid>
              </n-flex>
            </n-gi>

            <n-gi span="2">
              <PdPrefixPlanner
                v-if="draftGroup"
                :current-iface-name="currentIfaceName"
                :current-groups="currentPlannerGroups"
                :current-mode="currentMode"
                :edit-group="draftGroup"
                :other-configs-v2="otherLanConfigsV2"
                :selected-kind="selectedKind"
                :prefix-infos="prefixInfos"
                :expected-pd-lens="expectedPdLens"
                :draft-pd-pool-len="currentPdPoolLen"
                @interact-pool-index="onPlannerInteract"
              />
            </n-gi>
          </n-grid>

          <n-alert
            v-if="
              draftGroupHasResults &&
              !commitSaveState.canSave &&
              commitSaveState.saveError
            "
            type="error"
            :bordered="false"
          >
            {{ t(commitSaveState.saveError) }}
          </n-alert>
        </n-flex>
      </n-card>
    </n-flex>

    <template #footer>
      <n-flex justify="space-between">
        <n-flex :size="8">
          <n-popconfirm v-if="group" @positive-click="deleteCurrentGroup">
            <template #trigger>
              <n-button type="error" secondary>
                {{ t("lan_ipv6.delete") }}
              </n-button>
            </template>
            {{ t("lan_ipv6.prefix_group_delete_confirm") }}
          </n-popconfirm>

          <n-button @click="show = false">{{ t("lan_ipv6.cancel") }}</n-button>
        </n-flex>

        <n-button
          type="success"
          :disabled="draftGroupHasResults && !commitSaveState.canSave"
          @click="commit"
        >
          {{ t("lan_ipv6.confirm") }}
        </n-button>
      </n-flex>
    </template>
  </n-modal>

  <n-modal
    v-model:show="emptyDraftActionVisible"
    preset="card"
    style="width: 460px"
    :closable="false"
    :mask-closable="false"
    :auto-focus="false"
    :title="t('lan_ipv6.stale_selection_empty_title')"
  >
    <n-text>{{ t("lan_ipv6.stale_selection_empty_description") }}</n-text>
    <template #footer>
      <n-flex justify="end" :size="8">
        <n-button @click="emptyDraftActionVisible = false">
          {{ t("lan_ipv6.stale_selection_return_edit") }}
        </n-button>
        <n-button type="error" secondary @click="deleteCurrentGroup">
          {{ t("lan_ipv6.stale_selection_delete") }}
        </n-button>
        <n-button @click="cancelEmptyDraftAction">
          {{ t("lan_ipv6.stale_selection_cancel_edit") }}
        </n-button>
      </n-flex>
    </template>
  </n-modal>
</template>

<style scoped>
.kind-switch {
  border: 1px solid var(--n-border-color);
  border-radius: 10px;
  padding: 12px;
  cursor: pointer;
  background: color-mix(
    in srgb,
    var(--n-color) 68%,
    var(--n-color-embedded) 32%
  );
  color: var(--n-text-color);
  transition:
    border-color 0.15s ease,
    background-color 0.15s ease,
    transform 0.15s ease;
}

.kind-switch:hover {
  background: color-mix(in srgb, var(--n-color) 54%, var(--n-hover-color) 46%);
}

.kind-switch.active {
  border-color: var(--n-primary-color);
  background: color-mix(
    in srgb,
    var(--n-primary-color) 28%,
    var(--n-color) 72%
  );
}

.kind-switch.disabled {
  cursor: not-allowed;
  opacity: 0.5;
  background: color-mix(
    in srgb,
    var(--n-color) 55%,
    var(--n-color-embedded) 45%
  );
}

.kind-switch.disabled:hover {
  background: color-mix(
    in srgb,
    var(--n-color) 55%,
    var(--n-color-embedded) 45%
  );
}

.kind-switch-title {
  font-weight: 600;
}

.kind-switch-count {
  font-size: 12px;
  color: var(--n-text-color-3);
  margin-top: 4px;
}

.kind-switch-extra {
  margin-top: 10px;
}
</style>
