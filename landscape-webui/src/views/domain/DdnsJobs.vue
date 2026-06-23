<script lang="ts" setup>
import { get_wan_candidates } from "@/api/iface";
import { get_current_ip_prefix_info } from "@/api/service_ipv6pd";
import {
  delete_ddns_job,
  get_ddns_job_status,
  get_ddns_jobs,
  push_ddns_job,
  sync_ddns_job,
} from "@/api/domain/ddns";
import { get_dns_provider_profiles } from "@/api/domain/provider_profile";
import { useWindowSize } from "@vueuse/core";
import type {
  DdnsFamilyRuntime,
  DdnsJob,
  DdnsJobRuntime,
  DdnsRecordConfig,
  DdnsSource,
  DnsProviderProfile,
  IpFamily,
} from "@landscape-router/types/api/schemas";
import { computed, h, onMounted, ref } from "vue";
import {
  NButton,
  NFlex,
  NPopconfirm,
  NTag,
  useMessage,
  type DataTableColumns,
} from "naive-ui";
import ConfigModal from "@/components/common/ConfigModal.vue";
import { useFrontEndStore } from "@/stores/front_end_config";
import { useEnrolledDeviceStore } from "@/stores/enrolled_device";
import { useI18n } from "vue-i18n";

const { t } = useI18n();
const message = useMessage();
const frontEndStore = useFrontEndStore();
const items = ref<DdnsJob[]>([]);
const runtimeMap = ref<Map<string, DdnsJobRuntime>>(new Map());
const providerProfiles = ref<DnsProviderProfile[]>([]);
const ifaceOptions = ref<{ label: string; value: string }[]>([]);
const wanPdOptions = ref<
  { label: string; value: string; disabled?: boolean }[]
>([]);
type SourceInputItem =
  | { kind: "wan"; target_id: string; family: IpFamily }
  | {
      kind: "lan_device";
      target_id: string;
      wan_pd_id: string;
      family: "ipv6";
    };
const loading = ref(false);
const showModal = ref(false);
const showDetailDrawer = ref(false);
const saving = ref(false);
const syncingIds = ref<Set<string>>(new Set());
const editingId = ref<string | null>(null);
const detailJobId = ref<string | null>(null);
const formRef = ref();
const recordInputs = ref<string[]>([]);
const sourceInputs = ref<SourceInputItem[]>([]);
const { width: windowWidth } = useWindowSize();
const form = ref<DdnsJob>({
  name: "",
  enable: true,
  sources: [],
  zone_name: "",
  provider_profile_id: "",
  records: [],
});

const formEnabled = computed({
  get() {
    return form.value.enable ?? true;
  },
  set(value: boolean) {
    form.value.enable = value;
  },
});

const enrolledDeviceStore = useEnrolledDeviceStore();
const familyOptions = [
  { label: "IPv4", value: "ipv4" },
  { label: "IPv6", value: "ipv6" },
];
const deviceOptions = computed(() =>
  enrolledDeviceStore.bindings.map((d) => ({
    label: d.name,
    value: d.id!,
  })),
);
const sourceKindOptions = computed(() => [
  { label: t("cert.source_kind_wan"), value: "wan" },
  { label: t("cert.source_kind_lan_device"), value: "lan_device" },
]);

const rules = {
  name: {
    required: true,
    message: () => t("cert.job_name_required"),
    trigger: ["input", "blur"],
  },
  zone_name: {
    required: true,
    message: () => t("cert.zone_name_required"),
    trigger: ["input", "blur"],
  },
  provider_profile_id: {
    required: true,
    message: () => t("cert.provider_profile_required"),
    trigger: ["change", "blur"],
  },
};

const providerOptions = computed(() =>
  providerProfiles.value.map((item) => ({ label: item.name, value: item.id! })),
);
const selectedProviderProfile = computed(
  () =>
    providerProfiles.value.find(
      (item) => item.id === form.value.provider_profile_id,
    ) ?? null,
);
const selectedProviderDefaultTtl = computed(
  () => selectedProviderProfile.value?.ddns_default_ttl ?? 120,
);
const useProfileDefaultTtl = computed({
  get: () => form.value.ttl == null,
  set: (useProfileDefault) => {
    if (useProfileDefault) {
      form.value.ttl = undefined;
    } else {
      form.value.ttl = selectedProviderDefaultTtl.value;
    }
  },
});

const selectedDetailJob = computed(
  () => items.value.find((item) => item.id === detailJobId.value) ?? null,
);

const detailDrawerWidth = computed(() => {
  const width = windowWidth.value || 920;
  return width < 768 ? width : 920;
});

const detailDrawerTitle = computed(() => {
  if (!selectedDetailJob.value) return t("cert.ddns_job_details");
  return `${frontEndStore.MASK_INFO(selectedDetailJob.value.name)} · ${frontEndStore.MASK_INFO(selectedDetailJob.value.zone_name)}`;
});

function resetForm(item?: DdnsJob) {
  form.value = item
    ? JSON.parse(JSON.stringify(item))
    : {
        name: "",
        enable: true,
        sources: [],
        zone_name: "",
        provider_profile_id: providerProfiles.value[0]?.id ?? "",
        records: [],
      };
  editingId.value = item?.id ?? null;
  sourceInputs.value = item?.sources?.map((source) =>
    source.t === "local_wan"
      ? {
          kind: "wan" as const,
          target_id: source.iface_name,
          family: source.family,
        }
      : {
          kind: "lan_device" as const,
          target_id: source.device_id,
          wan_pd_id: source.wan_pd_id ?? "",
          family: "ipv6" as const,
        },
  ) ?? [
    {
      kind: "wan",
      target_id: ifaceOptions.value[0]?.value ?? "",
      family: "ipv6" as IpFamily,
    },
  ];
  recordInputs.value = item?.records?.map((record) => record.name) ?? ["@"];
}

async function refresh() {
  loading.value = true;
  try {
    const [jobs, runtimeStatuses, profiles, wanCandidates, prefixInfos] =
      await Promise.all([
        get_ddns_jobs(),
        get_ddns_job_status(),
        get_dns_provider_profiles(),
        get_wan_candidates(),
        get_current_ip_prefix_info(),
      ]);
    items.value = jobs;
    runtimeMap.value = new Map(
      runtimeStatuses.map((item) => [item.job_id, item]),
    );
    providerProfiles.value = profiles;
    ifaceOptions.value = wanCandidates.map((name: string) => ({
      label: name,
      value: name,
    }));
    wanPdOptions.value = Array.from(prefixInfos.entries()).map(
      ([key, value]) => ({
        label: key,
        value: key,
        disabled: value === null,
      }),
    );
  } finally {
    loading.value = false;
  }
}

function providerName(id: string) {
  return providerProfiles.value.find((item) => item.id === id)?.name ?? id;
}

function deviceName(id: string): string {
  return (
    enrolledDeviceStore.bindings.find((d) => d.id === id)?.name ??
    frontEndStore.MASK_INFO(id)
  );
}

function sourceTags(job: DdnsJob | null) {
  if (!job) return null;
  const tags = job.sources.map((source) =>
    source.t === "local_wan"
      ? h(
          NTag,
          { size: "small", type: "info" },
          {
            default: () =>
              `${frontEndStore.MASK_INFO(source.iface_name)} / ${source.family.toUpperCase()}`,
          },
        )
      : h(
          NTag,
          { size: "small", type: "success" },
          {
            default: () =>
              `${deviceName(source.device_id)}${source.wan_pd_id ? ` @${source.wan_pd_id}` : ""}`,
          },
        ),
  );
  return h(NFlex, { size: 4, wrap: true }, { default: () => tags });
}

function statusType(status?: string) {
  switch (status) {
    case "success":
      return "success";
    case "error":
      return "error";
    case "syncing":
      return "warning";
    default:
      return "default";
  }
}

function recordsSummary(job: DdnsJob) {
  return (job.records ?? [])
    .map((record) => frontEndStore.MASK_INFO(record.name))
    .join(", ");
}

function getJobRuntime(job: DdnsJob) {
  return job.id ? runtimeMap.value.get(job.id) : undefined;
}

function aggregateStatus(job: DdnsJob) {
  return getJobRuntime(job)?.status ?? "idle";
}

function renderFamilyStatus(status?: string) {
  return h(
    NTag,
    { size: "small", type: statusType(status) },
    () => status ?? "idle",
  );
}

function formatIp(ip?: string | null) {
  return ip ? frontEndStore.MASK_INFO(ip) : "-";
}

function formatError(err?: string | null) {
  return err ? frontEndStore.MASK_INFO(err) : "-";
}

function formatTimestamp(ts?: number | null) {
  if (!ts) return "-";
  return new Date(ts).toLocaleString();
}

function runtimeReasonLabel(reason?: string | null) {
  return reason ? t(`cert.ddns_reason_${reason}`) : "-";
}

function formatRetry(runtime?: {
  retryable?: boolean;
  next_retry_at?: number | null;
}) {
  if (!runtime?.retryable) return "-";
  return runtime.next_retry_at
    ? formatTimestamp(runtime.next_retry_at)
    : t("cert.retry_scheduled");
}

function formatRuntimeSummary(runtime?: {
  reason?: string | null;
  retryable?: boolean;
  next_retry_at?: number | null;
}) {
  if (!runtime) return "-";
  const reason = runtimeReasonLabel(runtime.reason);
  const retry = formatRetry(runtime);
  const summary =
    retry === "-" ? reason : `${reason} · ${t("cert.next_retry_at")}: ${retry}`;
  if (summary === "-") return summary;
  return summary ? frontEndStore.MASK_INFO(summary) : summary;
}

function fallbackFamilyRuntime(
  jobEnabled: boolean,
  recordEnabled: boolean,
): DdnsFamilyRuntime {
  const enabled = jobEnabled && recordEnabled;
  return {
    status: "idle",
    reason: enabled ? "pending" : "disabled",
    last_published_ip: undefined,
    message: undefined,
    last_error: undefined,
    last_sync_at: undefined,
    retryable: false,
    next_retry_at: undefined,
  };
}

function detailRecords(job: DdnsJob | null) {
  if (!job) return [];
  return (
    getJobRuntime(job)?.records ??
    (job.records ?? []).map((record) => ({
      name: record.name,
      ipv4: fallbackFamilyRuntime(job.enable ?? true, record.enable ?? true),
      ipv6: fallbackFamilyRuntime(job.enable ?? true, record.enable ?? true),
    }))
  );
}

function mergeRecordItems(records: string[], existing: DdnsRecordConfig[]) {
  const byKey = new Map(
    existing.map((record) => [record.name.toLowerCase(), record]),
  );
  return records.map((name) => {
    const old = byKey.get(name.toLowerCase());
    return old
      ? { ...old, name }
      : {
          name,
          enable: true,
        };
  });
}

function normalizeRecordInput(value: string) {
  const normalized = value.trim();
  if (normalized.toLowerCase() === "root") {
    return "@";
  }
  return normalized;
}

function updateRecordInput(index: number, value: string) {
  recordInputs.value[index] = value;
}

function createSourceInputItem(): SourceInputItem {
  return {
    kind: "wan",
    target_id: ifaceOptions.value[0]?.value ?? "",
    family: "ipv6",
  };
}

function ddnsSourceKey(item: DdnsSource) {
  return item.t === "local_wan"
    ? `${item.t}:${item.iface_name}:${item.family}`
    : `${item.t}:${item.device_id}:${item.wan_pd_id ?? "null"}:${item.family}`;
}

function updateSourceKind(index: number, value: "wan" | "lan_device") {
  if (value === "lan_device") {
    sourceInputs.value[index] = {
      kind: "lan_device",
      target_id: "",
      wan_pd_id: wanPdOptions.value[0]?.value ?? "",
      family: "ipv6",
    };
  } else {
    sourceInputs.value[index] = {
      kind: "wan",
      target_id: ifaceOptions.value[0]?.value ?? "",
      family: sourceInputs.value[index]?.family === "ipv4" ? "ipv4" : "ipv6",
    };
  }
}

function updateSourceTarget(index: number, value: string) {
  sourceInputs.value[index].target_id = value;
}

function updateSourceWanPd(index: number, value: string) {
  if (sourceInputs.value[index].kind === "lan_device") {
    (
      sourceInputs.value[index] as Extract<
        SourceInputItem,
        { kind: "lan_device" }
      >
    ).wan_pd_id = value;
  }
}

function updateSourceFamily(index: number, value: IpFamily) {
  if (sourceInputs.value[index].kind === "wan") {
    sourceInputs.value[index].family = value;
  }
}

function updateProviderProfile(value: string) {
  form.value.provider_profile_id = value;
  if (!useProfileDefaultTtl.value && form.value.ttl == null) {
    form.value.ttl = selectedProviderDefaultTtl.value;
  }
}

async function save() {
  try {
    await formRef.value?.validate();
    saving.value = true;
    const recordNames = recordInputs.value
      .map((item) => normalizeRecordInput(item))
      .filter(Boolean);

    const sources: DdnsSource[] = sourceInputs.value
      .filter((item) => item.target_id)
      .map((item) => {
        if (item.kind === "wan") {
          return {
            t: "local_wan" as const,
            iface_name: item.target_id,
            family: item.family,
          };
        }
        return {
          t: "enrolled_device" as const,
          device_id: item.target_id,
          wan_pd_id: item.wan_pd_id || undefined,
          family: "ipv6" as const,
        };
      });

    if (recordNames.length === 0) {
      throw new Error(t("cert.record_name_required"));
    }
    if (sources.length === 0) {
      throw new Error(t("cert.source_required"));
    }
    if (new Set(sources.map(ddnsSourceKey)).size !== sources.length) {
      throw new Error(t("cert.source_duplicate"));
    }

    await push_ddns_job({
      ...form.value,
      id: editingId.value ?? undefined,
      sources,
      ttl: useProfileDefaultTtl.value
        ? undefined
        : (form.value.ttl ?? selectedProviderDefaultTtl.value),
      records: mergeRecordItems(recordNames, form.value.records ?? []),
    });
    showModal.value = false;
    await refresh();
  } catch (e: any) {
    message.error(e?.response?.data || e?.message || "Operation failed");
  } finally {
    saving.value = false;
  }
}

async function remove(id: string) {
  await delete_ddns_job(id);
  await refresh();
}

async function syncNow(id: string) {
  syncingIds.value.add(id);
  try {
    await sync_ddns_job(id);
    await refresh();
  } finally {
    syncingIds.value.delete(id);
  }
}

function openDetailDrawer(job: DdnsJob) {
  detailJobId.value = job.id ?? null;
  showDetailDrawer.value = true;
}

const columns = computed<DataTableColumns<DdnsJob>>(() => [
  {
    title: t("cert.job_name"),
    key: "name",
    minWidth: 120,
    render: (row) => frontEndStore.MASK_INFO(row.name),
  },
  {
    title: t("cert.zone_name"),
    key: "zone_name",
    minWidth: 160,
    render: (row) => frontEndStore.MASK_INFO(row.zone_name),
  },
  {
    title: t("cert.records"),
    key: "records",
    minWidth: 220,
    render: (row) => recordsSummary(row) || "-",
  },
  {
    title: t("cert.source"),
    key: "source",
    minWidth: 140,
    render: (row) => sourceTags(row),
  },
  {
    title: t("cert.provider_profile"),
    key: "provider_profile_id",
    minWidth: 140,
    render: (row) =>
      frontEndStore.MASK_INFO(providerName(row.provider_profile_id)),
  },
  {
    title: t("common.enable"),
    key: "enable",
    width: 90,
    render: (row) =>
      h(
        NTag,
        { size: "small", type: row.enable ? "success" : "default" },
        () => (row.enable ? t("common.enable") : t("common.disable")),
      ),
  },
  {
    title: t("common.status"),
    key: "status",
    width: 100,
    render: (row) =>
      h(NTag, { size: "small", type: statusType(aggregateStatus(row)) }, () =>
        aggregateStatus(row),
      ),
  },
  {
    title: t("cert.cert_status_message"),
    key: "status_message",
    minWidth: 220,
    render: (row) => formatRuntimeSummary(getJobRuntime(row)),
  },
  {
    title: t("common.actions"),
    key: "actions",
    width: 360,
    render: (row) => [
      h(
        NButton,
        {
          size: "small",
          secondary: true,
          onClick: () => openDetailDrawer(row),
        },
        () => t("common.details"),
      ),
      h(
        NButton,
        {
          size: "small",
          type: "primary",
          secondary: true,
          style: "margin-left: 8px",
          loading: row.id ? syncingIds.value.has(row.id) : false,
          disabled: !row.enable,
          onClick: () => row.id && syncNow(row.id),
        },
        () => t("cert.sync_now"),
      ),
      h(
        NButton,
        {
          size: "small",
          secondary: true,
          style: "margin-left: 8px",
          onClick: () => {
            resetForm(row);
            showModal.value = true;
          },
        },
        () => t("common.edit"),
      ),
      h(
        NPopconfirm,
        { onPositiveClick: () => remove(row.id!) },
        {
          trigger: () =>
            h(
              NButton,
              {
                size: "small",
                type: "error",
                secondary: true,
                style: "margin-left: 8px",
              },
              () => t("common.delete"),
            ),
          default: () => t("common.confirm_delete"),
        },
      ),
    ],
  },
]);

onMounted(async () => {
  await Promise.all([refresh(), enrolledDeviceStore.UPDATE_INFO()]);
  if (!form.value.provider_profile_id && providerProfiles.value.length > 0) {
    form.value.provider_profile_id = providerProfiles.value[0].id!;
  }
  if (sourceInputs.value.length === 0) {
    sourceInputs.value = [
      {
        kind: "wan",
        target_id: ifaceOptions.value[0]?.value ?? "",
        family: "ipv6" as IpFamily,
      },
    ];
  }
});
</script>

<template>
  <n-flex vertical style="flex: 1">
    <n-flex justify="space-between">
      <n-button
        @click="
          resetForm();
          showModal = true;
        "
        >{{ t("common.create") }}</n-button
      >
      <n-button :loading="loading" @click="refresh">{{
        t("common.refresh")
      }}</n-button>
    </n-flex>

    <n-data-table
      :columns="columns"
      :data="items"
      :bordered="false"
      :single-line="false"
    />

    <n-drawer
      v-model:show="showDetailDrawer"
      placement="right"
      :width="detailDrawerWidth"
    >
      <n-drawer-content :title="detailDrawerTitle" closable>
        <template v-if="selectedDetailJob">
          <n-flex vertical :size="12">
            <n-flex :size="8" wrap>
              <n-tag size="small">{{
                frontEndStore.MASK_INFO(selectedDetailJob.zone_name)
              }}</n-tag>
              <component :is="() => sourceTags(selectedDetailJob)" />
              <n-tag
                size="small"
                :type="statusType(aggregateStatus(selectedDetailJob))"
              >
                {{ aggregateStatus(selectedDetailJob) }}
              </n-tag>
            </n-flex>

            <div>
              {{ formatRuntimeSummary(getJobRuntime(selectedDetailJob)) }}
            </div>

            <div class="ddns-detail-table-wrapper">
              <table class="ddns-detail-table">
                <thead>
                  <tr>
                    <th>{{ t("cert.record_name") }}</th>
                    <th>IPv4</th>
                    <th>IPv4 IP</th>
                    <th>{{ t("cert.cert_status_message") }}</th>
                    <th>{{ t("cert.next_retry_at") }}</th>
                    <th>IPv4 Error</th>
                    <th>IPv6</th>
                    <th>IPv6 IP</th>
                    <th>{{ t("cert.cert_status_message") }}</th>
                    <th>{{ t("cert.next_retry_at") }}</th>
                    <th>IPv6 Error</th>
                  </tr>
                </thead>
                <tbody>
                  <tr
                    v-for="record in detailRecords(selectedDetailJob)"
                    :key="record.name"
                  >
                    <td>{{ frontEndStore.MASK_INFO(record.name) }}</td>
                    <td>
                      <n-tag
                        size="small"
                        :type="statusType(record.ipv4.status)"
                      >
                        {{ record.ipv4.status ?? "idle" }}
                      </n-tag>
                    </td>
                    <td>{{ formatIp(record.ipv4.last_published_ip) }}</td>
                    <td>{{ formatRuntimeSummary(record.ipv4) }}</td>
                    <td>{{ formatRetry(record.ipv4) }}</td>
                    <td>{{ formatError(record.ipv4.last_error) }}</td>
                    <td>
                      <n-tag
                        size="small"
                        :type="statusType(record.ipv6.status)"
                      >
                        {{ record.ipv6.status ?? "idle" }}
                      </n-tag>
                    </td>
                    <td>{{ formatIp(record.ipv6.last_published_ip) }}</td>
                    <td>{{ formatRuntimeSummary(record.ipv6) }}</td>
                    <td>{{ formatRetry(record.ipv6) }}</td>
                    <td>{{ formatError(record.ipv6.last_error) }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </n-flex>
        </template>
      </n-drawer-content>
    </n-drawer>

    <ConfigModal
      v-model:show="showModal"
      v-model:enabled="formEnabled"
      :title="t('cert.ddns_jobs')"
      width="680px"
    >
      <n-form
        ref="formRef"
        :model="form"
        :rules="rules"
        label-placement="left"
        label-width="auto"
      >
        <n-form-item :label="t('cert.job_name')" path="name"
          ><n-input v-model:value="form.name"
        /></n-form-item>
        <n-form-item :label="t('cert.zone_name')" path="zone_name">
          <n-input v-model:value="form.zone_name" placeholder="example.com" />
        </n-form-item>
        <n-form-item :label="t('cert.records')">
          <n-dynamic-input v-model:value="recordInputs" :min="1">
            <template #default="{ value, index }">
              <n-input
                :value="value"
                :placeholder="t('cert.record_names_placeholder')"
                @update:value="updateRecordInput(index, $event)"
              />
            </template>
          </n-dynamic-input>
        </n-form-item>
        <n-form-item :label="t('cert.sources')">
          <n-dynamic-input
            v-model:value="sourceInputs"
            :min="1"
            :on-create="createSourceInputItem"
          >
            <template #default="{ value, index }">
              <n-flex style="width: 100%" :size="8" :wrap="false">
                <n-select
                  style="width: 110px"
                  :value="value.kind"
                  :options="sourceKindOptions"
                  @update:value="updateSourceKind(index, $event)"
                />
                <n-select
                  v-if="value.kind === 'wan'"
                  style="flex: 1"
                  :value="value.target_id"
                  :options="ifaceOptions"
                  @update:value="updateSourceTarget(index, $event)"
                />
                <template v-else>
                  <n-select
                    style="width: 120px"
                    :value="(value as any).wan_pd_id"
                    :options="wanPdOptions"
                    :placeholder="t('cert.select_wan_pd')"
                    @update:value="updateSourceWanPd(index, $event)"
                  />
                  <n-select
                    style="flex: 1"
                    :value="value.target_id"
                    :options="deviceOptions"
                    :placeholder="t('cert.select_device')"
                    @update:value="updateSourceTarget(index, $event)"
                  />
                </template>
                <n-select
                  style="width: 75px"
                  :value="value.family"
                  :options="
                    value.kind === 'wan'
                      ? familyOptions
                      : [{ label: 'IPv6', value: 'ipv6' }]
                  "
                  @update:value="updateSourceFamily(index, $event)"
                />
              </n-flex>
            </template>
          </n-dynamic-input>
        </n-form-item>
        <n-form-item
          :label="t('cert.provider_profile')"
          path="provider_profile_id"
        >
          <n-select
            :value="form.provider_profile_id"
            :options="providerOptions"
            @update:value="updateProviderProfile"
          />
        </n-form-item>
        <n-form-item :label="t('cert.ttl')">
          <n-flex vertical style="width: 100%" :size="8">
            <n-flex :wrap="false" align="center" style="width: 100%" :size="8">
              <n-switch v-model:value="useProfileDefaultTtl">
                <template #checked>{{ t("cert.follow_profile_ttl") }}</template>
                <template #unchecked>{{ t("cert.custom_ttl") }}</template>
              </n-switch>
              <n-input-number
                :value="
                  useProfileDefaultTtl ? selectedProviderDefaultTtl : form.ttl
                "
                :disabled="useProfileDefaultTtl"
                :min="1"
                :precision="0"
                style="flex: 1"
                @update:value="form.ttl = $event ?? undefined"
              />
            </n-flex>
            <div class="ddns-form-hint">
              {{
                useProfileDefaultTtl
                  ? `${t("cert.follow_profile_ttl_hint")} ${selectedProviderDefaultTtl}`
                  : t("cert.custom_ttl_hint")
              }}
            </div>
          </n-flex>
        </n-form-item>
      </n-form>

      <n-alert type="info" :show-icon="false" style="margin-top: 8px">
        {{ t("cert.zone_records_hint") }}
      </n-alert>

      <template #footer>
        <n-flex justify="space-between">
          <n-button @click="showModal = false">{{
            t("common.cancel")
          }}</n-button>
          <n-button type="primary" :loading="saving" @click="save">{{
            t("common.save")
          }}</n-button>
        </n-flex>
      </template>
    </ConfigModal>
  </n-flex>
</template>

<style scoped>
.ddns-detail-table-wrapper {
  overflow-x: auto;
}

.ddns-form-hint {
  color: rgba(128, 128, 128, 0.9);
  font-size: 12px;
}

.ddns-detail-table {
  width: 100%;
  border-collapse: collapse;
}

.ddns-detail-table th,
.ddns-detail-table td {
  padding: 8px 10px;
  border-bottom: 1px solid rgba(128, 128, 128, 0.18);
  text-align: left;
  vertical-align: top;
}

.ddns-detail-table th {
  font-weight: 600;
}
</style>
