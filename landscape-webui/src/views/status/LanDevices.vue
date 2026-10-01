<script lang="ts" setup>
import type { LanDeviceView } from "@/api/lan_device";
import type {
  EnrolledDevice,
  LanDeviceIpv6View,
} from "@landscape-router/types/api/schemas";
import { AddAlt, Edit } from "@vicons/carbon";
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

// MacAddr is typed as string[] in the ORVAL schema but serialized as string at runtime
function mac_as_string(mac: unknown): string {
  return mac as string;
}

// ── Filters ──
const iface_filter = ref<string | null>(null);
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
    mac_as_string(device.mac),
    device.display_name || device.hostname || mac_as_string(device.mac),
  );
}

// ── IPv6 display: one preferred address, the rest behind a tooltip ──
// Source priority matches the directory's ownership semantics:
// Static > DHCPv6 > SLAAC; link-local sorts last within a source.
function sort_ipv6(addrs: LanDeviceIpv6View[]): LanDeviceIpv6View[] {
  const rank = (source: string) =>
    source === "static" ? 0 : source === "dhcpv6" ? 1 : 2;
  const link_local = (ip: string) => ip.toLowerCase().startsWith("fe80:");
  return [...addrs].sort(
    (a, b) =>
      rank(a.source) - rank(b.source) ||
      Number(link_local(a.ip)) - Number(link_local(b.ip)),
  );
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
  const targetMac = mac_as_string(device.mac);
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
  <n-flex vertical style="flex: 1">
    <n-flex justify="space-between" align="center">
      <n-flex align="center" size="small">
        <span>{{ t("lan_device.filter_iface") }}</span>
        <n-select
          v-model:value="iface_filter"
          :options="iface_options"
          size="small"
          style="width: 160px"
        />
        <span>{{ t("lan_device.filter_online") }}</span>
        <n-select
          v-model:value="online_filter"
          :options="online_options"
          size="small"
          style="width: 120px"
        />
      </n-flex>
      <n-button :loading="loading" @click="refresh">{{
        t("common.refresh")
      }}</n-button>
    </n-flex>

    <n-table
      v-if="show_devices.length > 0"
      :bordered="true"
      striped
      size="small"
    >
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
        <tr v-for="device in show_devices" :key="device.entry_id">
          <td class="assign-item">{{ device_name(device) }}</td>
          <td class="assign-item">
            <n-flex justify="center" align="center" size="small">
              <span>{{
                frontEndStore.MASK_INFO(mac_as_string(device.mac))
              }}</span>
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
          <td class="assign-item">
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
                :type="device.ipv4.source === 'static' ? 'info' : 'default'"
              >
                {{ t(`lan_device.source_${device.ipv4.source}`) }}
              </n-tag>
              <n-tooltip
                v-if="
                  hasConfiguredIpv4Mismatch(
                    device.ipv4.ip,
                    mac_as_string(device.mac),
                    device.iface_name,
                  )
                "
                trigger="hover"
              >
                <template #trigger>
                  <n-tag size="tiny" type="warning" :bordered="false">IP</n-tag>
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
                      getConfiguredIpv4(mac_as_string(device.mac)) || "",
                    )
                  }}
                </div>
              </n-tooltip>
            </n-flex>
            <span v-else>—</span>
          </td>
          <td class="assign-item">
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
                  primary_ipv6_source(device) === 'slaac' ? 'default' : 'info'
                "
              >
                {{ t(`lan_device.source_${primary_ipv6_source(device)}`) }}
              </n-tag>
              <n-tooltip v-if="rest_ipv6(device).length > 0" trigger="hover">
                <template #trigger>
                  <n-tag size="tiny" :bordered="false"
                    >+{{ rest_ipv6(device).length }}</n-tag
                  >
                </template>
                <div v-for="addr in rest_ipv6(device)" :key="addr.ip">
                  {{ frontEndStore.MASK_INFO(addr.ip) }} ·
                  {{ t(`lan_device.source_${addr.source}`) }}
                </div>
              </n-tooltip>
            </n-flex>
            <span v-else>—</span>
          </td>
          <td class="assign-item">
            {{ device.iface_name ?? t("lan_device.unknown") }}
          </td>
          <td class="assign-item">
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
          <td class="assign-item">
            <n-time
              v-if="device.last_active > 0"
              :time="device.last_active"
              :time-zone="prefStore.timezone"
            />
            <span v-else>—</span>
          </td>
          <td class="assign-item">
            <PresenceDots
              :presence="device.arp_presence"
              :last-seen="device.arp_last_seen"
            />
          </td>
          <td class="assign-item">
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
          <td class="assign-item">
            <n-button size="tiny" quaternary circle @click="quickBind(device)">
              <template #icon>
                <n-icon>
                  <Edit
                    v-if="
                      enrolledDeviceStore.GET_BINDING_ID(
                        mac_as_string(device.mac),
                      )
                    "
                  />
                  <AddAlt v-else />
                </n-icon>
              </template>
            </n-button>
          </td>
        </tr>
      </tbody>
    </n-table>
    <n-empty v-else style="flex: 1" :description="t('lan_device.empty')" />
  </n-flex>

  <EnrolledDeviceEditModal
    v-model:show="showQuickBind"
    :rule_id="bindRuleId"
    :initial-values="initialValues"
    @refresh="refresh"
  />
</template>

<style scoped>
.assign-head {
  text-align: center;
}
.assign-item {
  text-align: center;
}
</style>
