<script lang="ts" setup>
import type {
  LanDeviceView,
  EnrolledDevice,
  LanDeviceIpv6View,
} from "@landscape-router/types/api/schemas";

import { useMobileLayout } from "@/composables/useMobileLayout";
import { AddAlt, ChevronDown, ChevronUp, Edit } from "@vicons/carbon";
import { computed, nextTick, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import type { CountdownInst, SelectOption } from "naive-ui";

import { useFrontEndStore } from "@/stores/front_end_config";
import { usePreferenceStore } from "@/stores/preference";
import { useEnrolledDeviceStore } from "@/stores/enrolled_device";
import { useLanDeviceStore } from "@/stores/lan_device";
import EnrolledDeviceEditModal from "@/components/device/EnrolledDeviceEditModal.vue";
import PresenceDots from "@/components/lan_device/PresenceDots.vue";

const { t } = useI18n();
const frontEndStore = useFrontEndStore();
const prefStore = usePreferenceStore();
const enrolledDeviceStore = useEnrolledDeviceStore();
const lanDeviceStore = useLanDeviceStore();

const loading = ref(false);
const mobile = useMobileLayout();
const expandedDevice = ref<string>();

async function refresh() {
  loading.value = true;
  try {
    await Promise.all([
      lanDeviceStore.UPDATE_INFO(),
      enrolledDeviceStore.UPDATE_INFO(),
    ]);
  } finally {
    loading.value = false;
  }
}

// ── Filters ──
const iface_filter = ref<string | null>("all");
const online_filter = ref<string | null>("all");

const iface_options = computed<SelectOption[]>(() => {
  const names = new Set<string>();
  for (const device of lanDeviceStore.devices) {
    if (device.iface_name) names.add(device.iface_name);
  }
  return [
    { label: t("lan_device.filter_all"), value: "all" },
    ...Array.from(names)
      .sort()
      .map((name) => ({ label: name, value: name })),
  ];
});

const online_options = computed<SelectOption[]>(() => [
  { label: t("lan_device.filter_all"), value: "all" },
  { label: t("lan_device.online_yes"), value: "online" },
  { label: t("lan_device.online_no"), value: "offline" },
]);

const show_devices = computed<LanDeviceView[]>(() => {
  return lanDeviceStore.devices.filter((device) => {
    if (iface_filter.value && iface_filter.value !== "all") {
      if ((device.iface_name ?? "") !== iface_filter.value) return false;
    }
    if (online_filter.value === "online" && !device.online) return false;
    if (online_filter.value === "offline" && device.online) return false;
    return true;
  });
});

// ── Static-IP mismatch warning (same rule as the retired DHCPv4 table) ──
function bindingAppliesToIface(
  binding: EnrolledDevice | undefined,
  iface_name?: string,
): boolean {
  if (!binding) return false;
  return !binding.iface_name || binding.iface_name === iface_name;
}

function hasConfiguredIpv4Mismatch(
  observedIp: string,
  mac?: string,
  iface_name?: string,
): boolean {
  const binding = enrolledDeviceStore.GET_BINDING(mac);
  if (!bindingAppliesToIface(binding, iface_name)) return false;
  const configuredIpv4 = binding?.ipv4;
  return !!configuredIpv4 && configuredIpv4 !== observedIp;
}

function getConfiguredIpv4(mac?: string): string | undefined {
  return enrolledDeviceStore.GET_BINDING(mac)?.ipv4;
}

function device_name(device: LanDeviceView): string {
  return enrolledDeviceStore.GET_NAME_WITH_FALLBACK(
    device.mac,
    device.display_name || device.hostname || device.mac,
  );
}

// ── IPv6 display: one preferred address, the rest behind a tooltip ──
// Source priority matches the directory's ownership semantics:
// Static > DHCPv6 > SLAAC > Link Local.
function sort_ipv6(addrs: LanDeviceIpv6View[]): LanDeviceIpv6View[] {
  const rank = (source: string) =>
    source === "static"
      ? 0
      : source === "dhcpv6"
        ? 1
        : source === "slaac"
          ? 2
          : 3;
  return [...addrs].sort((a, b) => rank(a.source) - rank(b.source));
}

function primary_ipv6(device: LanDeviceView): string {
  return sort_ipv6(device.ipv6_addrs)[0]?.ip ?? "";
}

function primary_ipv6_source(device: LanDeviceView): string {
  return sort_ipv6(device.ipv6_addrs)[0]?.source ?? "";
}

function rest_ipv6(device: LanDeviceView): LanDeviceIpv6View[] {
  return sort_ipv6(device.ipv6_addrs).slice(1);
}

// IPv6 'static' means the address is generated from the device's enrolled
// static suffix; label it distinctly from an IPv4 static address.
// 'link_local' is an API scope classification: fe80::/10 addresses are
// auto-generated on every interface and carry no assignment semantics.
function ipv6_source_label(source: string): string {
  if (source === "static") return t("lan_device.source_static_suffix");
  return t(`lan_device.source_${source}`);
}

// ── Lease countdown ──
const countdownRefs = ref<CountdownInst[]>([]);

watch(
  () => lanDeviceStore.devices,
  async () => {
    await nextTick();
    countdownRefs.value.forEach((c) => c?.reset());
  },
);

let refreshTimer: number | null = null;
function on_countdown_finish() {
  if (refreshTimer) clearTimeout(refreshTimer);
  refreshTimer = window.setTimeout(async () => {
    await refresh();
    refreshTimer = null;
  }, 3000);
}

// n-countdown's `duration` is milliseconds remaining from now, not a
// target timestamp; clamp at zero so an expired lease finishes (and
// triggers the debounced refresh) instead of counting up backwards.
function lease_remaining_ms(device: LanDeviceView): number {
  const lease = device.dhcp_lease;
  if (!lease) return 0;
  return Math.max(0, lease.expires - Date.now());
}

// ── Quick bind ──
const showQuickBind = ref(false);
const initialValues = ref<{
  mac?: string;
  ipv4?: string;
  name?: string;
  iface_name?: string;
}>({});
const bindRuleId = ref<string | null>(null);

function quickBind(device: LanDeviceView) {
  const targetMac = device.mac;
  if (!targetMac) return;
  bindRuleId.value = enrolledDeviceStore.GET_BINDING_ID(targetMac);
  initialValues.value = {
    mac: targetMac,
    ipv4: device.ipv4?.ip,
    name: device.display_name || device.hostname || "",
    iface_name: device.iface_name,
  };
  showQuickBind.value = true;
}
</script>

<template>
  <n-flex vertical style="flex: 1; overflow: hidden; min-height: 0">
    <div class="device-toolbar">
      <div class="device-filters">
        <label>
          <span>{{ t("lan_device.filter_iface") }}</span>
          <n-select
            v-model:value="iface_filter"
            :options="iface_options"
            size="small"
            style="width: 160px"
          />
        </label>
        <label>
          <span>{{ t("lan_device.filter_online") }}</span>
          <n-select
            v-model:value="online_filter"
            :options="online_options"
            size="small"
            style="width: 120px"
          />
        </label>
      </div>
      <n-button :loading="loading" @click="refresh">{{
        t("common.refresh")
      }}</n-button>
    </div>

    <n-scrollbar v-if="show_devices.length > 0" class="table-scroll">
      <n-table class="device-table" :bordered="true" striped size="small">
        <thead>
          <tr>
            <th class="assign-head">{{ t("lan_device.name") }}</th>
            <th class="assign-head">{{ t("lan_device.mac_addr") }}</th>
            <th class="assign-head">{{ t("lan_device.ipv4") }}</th>
            <th class="assign-head">{{ t("lan_device.ipv6") }}</th>
            <th class="assign-head">{{ t("lan_device.iface") }}</th>
            <th class="assign-head">{{ t("lan_device.online") }}</th>
            <th class="assign-head">{{ t("lan_device.last_active") }}</th>
            <th class="assign-head" style="width: 168px">
              {{ t("lan_device.arp_presence") }}
            </th>
            <th class="assign-head">{{ t("lan_device.lease_left") }}</th>
            <th class="assign-head" style="width: 60px">
              {{ t("lan_device.actions") }}
            </th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="device in show_devices"
            :key="device.entry_id"
            :class="{ expanded: expandedDevice === device.entry_id }"
          >
            <td class="assign-item device-name">
              <button
                v-if="mobile"
                type="button"
                :aria-expanded="expandedDevice === device.entry_id"
                @click="
                  expandedDevice =
                    expandedDevice === device.entry_id
                      ? undefined
                      : device.entry_id
                "
              >
                <n-icon
                  :component="
                    expandedDevice === device.entry_id ? ChevronUp : ChevronDown
                  "
                />
                {{ device_name(device) || t("common.unnamed") }}
              </button>
              <template v-else>{{ device_name(device) }}</template>
            </td>
            <td class="assign-item" :data-label="t('lan_device.mac_addr')">
              <n-flex justify="center" align="center" size="small">
                <span>{{ frontEndStore.MASK_INFO(device.mac) }}</span>
                <n-tag
                  v-if="device.device_id"
                  size="tiny"
                  type="primary"
                  :bordered="false"
                >
                  {{ t("lan_device.enrolled") }}
                </n-tag>
              </n-flex>
            </td>
            <td
              class="assign-item device-ipv4"
              :data-label="t('lan_device.ipv4')"
            >
              <n-flex
                v-if="device.ipv4"
                justify="center"
                align="center"
                size="small"
              >
                <span>{{ frontEndStore.MASK_INFO(device.ipv4.ip) }}</span>
                <n-tag
                  size="tiny"
                  :bordered="false"
                  :type="
                    device.ipv4.source === 'static'
                      ? 'info'
                      : device.ipv4.source === 'arp'
                        ? 'warning'
                        : 'default'
                  "
                >
                  {{ t(`lan_device.source_${device.ipv4.source}`) }}
                </n-tag>
                <n-tooltip
                  v-if="
                    hasConfiguredIpv4Mismatch(
                      device.ipv4.ip,
                      device.mac,
                      device.iface_name,
                    )
                  "
                  trigger="hover"
                >
                  <template #trigger>
                    <n-tag size="tiny" type="warning" :bordered="false"
                      >IP</n-tag
                    >
                  </template>
                  <div>{{ t("device.lease_ip_mismatch") }}</div>
                  <div>
                    {{ t("device.observed_ip") }}:
                    {{ frontEndStore.MASK_INFO(device.ipv4.ip) }}
                  </div>
                  <div>
                    {{ t("device.configured_ip") }}:
                    {{
                      frontEndStore.MASK_INFO(
                        getConfiguredIpv4(device.mac) || "",
                      )
                    }}
                  </div>
                </n-tooltip>
              </n-flex>
              <span v-else>—</span>
            </td>
            <td class="assign-item" :data-label="t('lan_device.ipv6')">
              <n-flex
                v-if="device.ipv6_addrs.length > 0"
                justify="center"
                align="center"
                size="small"
              >
                <span>{{ frontEndStore.MASK_INFO(primary_ipv6(device)) }}</span>
                <n-tag
                  size="tiny"
                  :bordered="false"
                  :type="
                    ['slaac', 'link_local'].includes(
                      primary_ipv6_source(device),
                    )
                      ? 'default'
                      : 'info'
                  "
                >
                  {{ ipv6_source_label(primary_ipv6_source(device)) }}
                </n-tag>
                <template v-if="mobile">
                  <span v-for="addr in rest_ipv6(device)" :key="addr.ip"
                    >{{ frontEndStore.MASK_INFO(addr.ip) }} ·
                    {{ ipv6_source_label(addr.source) }}</span
                  >
                </template>
                <n-tooltip
                  v-else-if="rest_ipv6(device).length > 0"
                  trigger="hover"
                >
                  <template #trigger>
                    <n-tag size="tiny" :bordered="false"
                      >+{{ rest_ipv6(device).length }}</n-tag
                    >
                  </template>
                  <div v-for="addr in rest_ipv6(device)" :key="addr.ip">
                    {{ frontEndStore.MASK_INFO(addr.ip) }} ·
                    {{ ipv6_source_label(addr.source) }}
                  </div>
                </n-tooltip>
              </n-flex>
              <span v-else>—</span>
            </td>
            <td class="assign-item" :data-label="t('lan_device.iface')">
              {{ device.iface_name ?? t("lan_device.unknown") }}
            </td>
            <td
              class="assign-item device-online"
              :data-label="t('lan_device.online')"
            >
              <n-tag
                size="small"
                :type="device.online ? 'success' : 'default'"
                :bordered="false"
              >
                {{
                  device.online
                    ? t("lan_device.online_yes")
                    : t("lan_device.online_no")
                }}
              </n-tag>
            </td>
            <td class="assign-item" :data-label="t('lan_device.last_active')">
              <n-time
                v-if="device.last_active > 0"
                :time="device.last_active"
                :time-zone="prefStore.timezone"
              />
              <span v-else>—</span>
            </td>
            <td class="assign-item" :data-label="t('lan_device.arp_presence')">
              <PresenceDots
                :presence="device.arp_presence"
                :last-seen="device.arp_last_seen"
              />
            </td>
            <td class="assign-item" :data-label="t('lan_device.lease_left')">
              <n-tooltip v-if="device.dhcp_lease" trigger="hover">
                <template #trigger>
                  <n-countdown
                    ref="countdownRefs"
                    @finish="on_countdown_finish"
                    :duration="lease_remaining_ms(device)"
                    :active="true"
                  />
                </template>
                <div>
                  {{ t("lan_device.lease_ip") }}:
                  {{ frontEndStore.MASK_INFO(device.dhcp_lease.ip) }}
                </div>
                <div>
                  {{ t("lan_device.lease_last_request") }}:
                  <n-time
                    :time="device.dhcp_lease.last_request"
                    :time-zone="prefStore.timezone"
                  />
                </div>
              </n-tooltip>
              <span v-else>—</span>
            </td>
            <td class="assign-item" :data-label="t('lan_device.actions')">
              <n-button
                :size="mobile ? 'small' : 'tiny'"
                :quaternary="!mobile"
                :circle="!mobile"
                :disabled="!device.mac"
                :aria-label="
                  t(
                    enrolledDeviceStore.GET_BINDING_ID(device.mac)
                      ? 'device.edit_title'
                      : 'device.add_title',
                  )
                "
                @click="quickBind(device)"
              >
                <template #icon>
                  <n-icon>
                    <Edit
                      v-if="enrolledDeviceStore.GET_BINDING_ID(device.mac)"
                    />
                    <AddAlt v-else />
                  </n-icon>
                </template>
                <template v-if="mobile">{{
                  t(
                    enrolledDeviceStore.GET_BINDING_ID(device.mac)
                      ? "device.edit_title"
                      : "device.add_title",
                  )
                }}</template>
              </n-button>
            </td>
          </tr>
        </tbody>
      </n-table>
    </n-scrollbar>
    <n-empty
      v-else
      style="flex: 1"
      :description="
        t(
          lanDeviceStore.devices.length
            ? 'lan_device.no_matches'
            : 'lan_device.empty',
        )
      "
    >
      <template v-if="lanDeviceStore.devices.length" #extra>
        <n-button
          size="small"
          @click="
            iface_filter = 'all';
            online_filter = 'all';
          "
          >{{ t("common.clear_filters") }}</n-button
        >
      </template>
    </n-empty>
  </n-flex>

  <EnrolledDeviceEditModal
    v-model:show="showQuickBind"
    :rule_id="bindRuleId"
    :initial-values="initialValues"
    @refresh="refresh"
  />
</template>

<style scoped>
.device-toolbar,
.device-filters,
.device-filters label {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
}
.device-toolbar {
  justify-content: space-between;
}
@media (max-width: 768px) {
  .device-filters {
    flex: 1;
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .device-filters label {
    display: grid;
    gap: 4px;
  }
  .device-filters :deep(.n-select) {
    width: 100% !important;
  }
  .device-toolbar {
    align-items: end;
  }
  .device-table {
    display: block;
    border: 0;
    background: transparent;
  }
  .device-table thead {
    display: none;
  }
  .device-table tbody {
    display: grid;
    gap: 8px;
  }
  .device-table tbody tr {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    align-items: center;
    gap: 6px 8px;
    border: 1px solid var(--n-merged-border-color);
    border-radius: 6px;
    padding: 12px;
    background: var(--n-td-color);
  }
  .device-table tbody td.assign-item {
    padding: 0;
    text-align: start;
    background: transparent;
    border: 0;
    overflow-wrap: anywhere;
  }
  .device-name {
    grid-area: 1 / 1;
  }
  .device-name button {
    display: flex;
    align-items: center;
    gap: 6px;
    min-height: 32px;
    font: inherit;
    font-weight: 600;
    color: inherit;
    text-align: start;
    background: none;
    border: 0;
    cursor: pointer;
  }
  .device-online {
    grid-area: 1 / 2;
  }
  .device-ipv4 {
    grid-area: 2 / 1 / 3 / -1;
  }
  .device-ipv4 > div {
    justify-content: flex-start !important;
  }
  .device-table td:not(.device-name, .device-online, .device-ipv4) {
    display: none;
  }
  .device-table tr.expanded td:not(.device-name, .device-online, .device-ipv4) {
    display: flex;
    grid-column: 1 / -1;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    padding-block: 5px;
  }
  .expanded td:not(.device-name, .device-online, .device-ipv4)::before {
    content: attr(data-label);
    flex-shrink: 0;
    color: var(--n-th-text-color);
  }
}

.table-scroll {
  flex: 1;
  min-height: 0;
}
.assign-head {
  text-align: center;
  position: sticky;
  top: 0;
  z-index: 1;
}
.assign-item {
  text-align: center;
}
</style>
