<script lang="ts" setup>
import { sleep } from "@/lib/util";
import type { ArpScanInfo, DHCPv4OfferInfo } from "@/api/service_dhcp_v4";
import type { DHCPv4OfferInfoItem } from "@landscape-router/types/api/schemas";
import { CountdownInst } from "naive-ui";
import { computed, nextTick, ref, watch } from "vue";
import { useI18n } from "vue-i18n";

import { useFrontEndStore } from "@/stores/front_end_config";
import { usePreferenceStore } from "@/stores/preference";
const prefStore = usePreferenceStore();
import { mask_string } from "@/lib/common";
import { Key } from "@vicons/tabler";
import { AddAlt, Edit } from "@vicons/carbon";
import { useEnrolledDeviceStore } from "@/stores/enrolled_device";
import EnrolledDeviceEditModal from "@/components/device/EnrolledDeviceEditModal.vue";
import type { EnrolledDevice } from "@landscape-router/types/api/schemas";

const frontEndStore = useFrontEndStore();
const enrolledDeviceStore = useEnrolledDeviceStore();
const { t } = useI18n();
const emit = defineEmits(["refresh"]);
type Props = {
  arp_info: ArpScanInfo[];
  info: DHCPv4OfferInfo;
  iface_name: string;
};

interface ArpInfo {
  macs: Set<string>;
  ip_status: boolean[];
}

const props = withDefaults(defineProps<Props>(), {});

// MacAddr is typed as string[] in ORVAL schema but serialized as string at runtime
function mac_as_string(mac: unknown): string {
  return mac as string;
}

function caculate_time(item: DHCPv4OfferInfoItem): number {
  const expire_time =
    (item.relative_active_time + item.expire_time) * 1000 +
    props.info.boot_time;
  return expire_time - new Date().getTime();
}

function request_time(item: DHCPv4OfferInfoItem): number {
  return item.relative_active_time * 1000 + props.info.boot_time;
}

function ipv4_to_number(ip: string): number {
  const parts = ip.split(".").map(Number);
  if (
    parts.length !== 4 ||
    parts.some((part) => Number.isNaN(part) || part < 0 || part > 255)
  ) {
    return Number.POSITIVE_INFINITY;
  }

  return (
    parts[0] * 256 * 256 * 256 +
    parts[1] * 256 * 256 +
    parts[2] * 256 +
    parts[3]
  );
}

function compare_ipv4(a: string, b: string): number {
  const aNum = ipv4_to_number(a);
  const bNum = ipv4_to_number(b);

  if (aNum === bNum) {
    return a.localeCompare(b);
  }

  return aNum - bNum;
}

const show_item = computed(() => {
  let reuslt = [];
  for (const each of props.info.offered_ips) {
    reuslt.push({
      real_request_time: request_time(each),
      real_expire_time: caculate_time(each),
      ...each,
      mac: mac_as_string(each.mac),
    });
  }
  reuslt.sort((a, b) => compare_ipv4(a.ip, b.ip));
  return reuslt;
});

const not_current_round_ips = computed(() => {
  let ips = new Set(show_item.value.map((e) => e.ip));
  let not_current_round_ips = [];
  for (const [key, value] of arp_ip_map.value) {
    if (!ips.has(key)) {
      not_current_round_ips.push({
        ip: key,
        ip_status: value,
      });
    }
  }
  not_current_round_ips.sort((a, b) => compare_ipv4(a.ip, b.ip));
  return not_current_round_ips;
});

const countdownRefs = ref<CountdownInst[]>([]);

watch(show_item, async () => {
  await nextTick();
  console.log(countdownRefs);
  countdownRefs.value.forEach((c) => c?.reset());
});

let refreshTimer: number | null = null;
async function finish() {
  if (refreshTimer) {
    clearTimeout(refreshTimer);
  }

  refreshTimer = window.setTimeout(async () => {
    emit("refresh");
    refreshTimer = null;
  }, 3000);
}

const arp_ip_map = computed(() => {
  return build_ip_map(props.arp_info);
});

function build_ip_map(data: ArpScanInfo[]): Map<string, ArpInfo> {
  const map: Map<string, ArpInfo> = new Map();

  if (data) {
    data.forEach((scan, idx) => {
      scan.infos.forEach((item) => {
        if (!map.has(item.ip)) {
          map.set(item.ip, {
            macs: new Set(),
            ip_status: Array(data.length).fill(false),
          });
        }
        const arr = map.get(item.ip)!;
        arr.ip_status[idx] = true;
        arr.macs.add(mac_as_string(item.mac));
      });
    });
  }

  return map;
}

function getBindingByMac(mac?: string): EnrolledDevice | undefined {
  return enrolledDeviceStore.GET_BINDING(mac);
}

function bindingAppliesToCurrentIface(binding?: EnrolledDevice): boolean {
  if (!binding) return false;
  return !binding.iface_name || binding.iface_name === props.iface_name;
}

function hasConfiguredIpv4Mismatch(observedIp: string, mac?: string): boolean {
  const binding = getBindingByMac(mac);
  if (!bindingAppliesToCurrentIface(binding)) return false;

  const configuredIpv4 = binding?.ipv4;
  return !!configuredIpv4 && configuredIpv4 !== observedIp;
}

function getConfiguredIpv4(mac?: string): string | undefined {
  const binding = getBindingByMac(mac);
  if (!bindingAppliesToCurrentIface(binding)) return undefined;
  return binding?.ipv4;
}

const showQuickBind = ref(false);
const initialValues = ref<{
  mac?: string;
  ipv4?: string;
  name?: string;
  iface_name?: string;
}>({});
const bindRuleId = ref<string | null>(null);

function quickBind(ip: string, mac?: string, hostname?: string | null) {
  const targetMac = mac || Array.from(arp_ip_map.value.get(ip)?.macs || [])[0];
  if (!targetMac) return;

  const existingId = enrolledDeviceStore.GET_BINDING_ID(targetMac);
  bindRuleId.value = existingId;
  initialValues.value = {
    mac: targetMac,
    ipv4: ip,
    name: hostname || "",
    iface_name: props.iface_name,
  };
  showQuickBind.value = true;
}
</script>

<template>
  <!-- {{ info }} -->
  <!-- {{ arp_ip_map }} -->
  <!-- {{ not_current_round_ips }} -->
  <n-card size="small" :title="iface_name">
    <n-table v-if="info" :bordered="true" striped>
      <thead>
        <tr>
          <th class="assign-head" style="width: 20%">
            {{ t("dhcp_v4.assigned.hostname") }}
          </th>
          <th class="assign-head">
            <Notice>
              {{ t("dhcp_v4.assigned.mac_addr") }}
              <template #msg>
                {{ t("dhcp_v4.assigned.mac_tip_1") }}
              </template>
            </Notice>
          </th>
          <th class="assign-head">
            {{ t("dhcp_v4.assigned.assigned_ip") }}
          </th>
          <th class="assign-head">
            {{ t("dhcp_v4.assigned.latest_request") }}
          </th>
          <th class="assign-head">
            <Notice>
              {{ t("dhcp_v4.assigned.lease_left") }}
              <template #msg>{{ t("dhcp_v4.assigned.expire_time") }}</template>
            </Notice>
          </th>
          <th class="assign-head" style="width: 168px">
            <Notice>
              {{ t("dhcp_v4.assigned.online_24h") }}
              <template #msg>
                {{ t("dhcp_v4.assigned.online_24h_tip_1") }} <br />
                {{ t("dhcp_v4.assigned.online_24h_tip_2") }}
              </template>
            </Notice>
          </th>
          <th class="assign-head" style="width: 80px">
            {{ t("dhcp_v4.assigned.actions") }}
          </th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="item in show_item">
          <td class="assign-item">
            {{
              enrolledDeviceStore.GET_NAME_WITH_FALLBACK(
                item.mac,
                item.hostname,
              )
            }}
          </td>
          <td class="assign-item">
            <DHCPMacExhibit
              :mac="item.mac"
              :macs="arp_ip_map.get(item.ip)?.macs"
            >
            </DHCPMacExhibit>
          </td>
          <td class="assign-item">
            <n-flex justify="center" align="center" size="small">
              <span>{{ frontEndStore.MASK_INFO(item.ip) }}</span>
              <n-tooltip
                v-if="hasConfiguredIpv4Mismatch(item.ip, item.mac)"
                trigger="hover"
              >
                <template #trigger>
                  <n-tag size="small" type="warning" :bordered="false">
                    IP
                  </n-tag>
                </template>
                <div>{{ t("device.lease_ip_mismatch") }}</div>
                <div>
                  {{ t("device.observed_ip") }}:
                  {{ frontEndStore.MASK_INFO(item.ip) }}
                </div>
                <div>
                  {{ t("device.configured_ip") }}:
                  {{
                    frontEndStore.MASK_INFO(getConfiguredIpv4(item.mac) || "")
                  }}
                </div>
              </n-tooltip>
            </n-flex>
          </td>

          <td class="assign-item">
            <n-time
              :time="item.real_request_time"
              :time-zone="prefStore.timezone"
            ></n-time>
          </td>
          <td class="assign-item">
            <!-- {{ item.real_expire_time }} -->
            <n-flex justify="center" v-if="item.is_static">
              {{ t("dhcp_v4.assigned.static_assigned") }}
            </n-flex>
            <n-countdown
              v-else
              ref="countdownRefs"
              @finish="finish"
              :duration="item.real_expire_time"
              :active="true"
            />
          </td>

          <td class="assign-item">
            <OnlineStatus
              :ip_status="arp_ip_map.get(item.ip)?.ip_status"
            ></OnlineStatus>
          </td>
          <td class="assign-item">
            <n-button
              size="tiny"
              quaternary
              circle
              @click="quickBind(item.ip, item.mac, item.hostname)"
            >
              <template #icon>
                <n-icon>
                  <Edit v-if="enrolledDeviceStore.GET_BINDING_ID(item.mac)" />
                  <AddAlt v-else />
                </n-icon>
              </template>
            </n-button>
          </td>
        </tr>

        <tr v-for="item in not_current_round_ips">
          <td class="not-assign-item">
            {{
              enrolledDeviceStore.GET_NAME_WITH_FALLBACK(
                Array.from(arp_ip_map.get(item.ip)?.macs || [])[0],
                t("dhcp_v4.assigned.unknown"),
              )
            }}
          </td>
          <td class="not-assign-item">
            <DHCPMacExhibit :macs="arp_ip_map.get(item.ip)?.macs">
            </DHCPMacExhibit>
          </td>
          <td class="not-assign-item">
            <n-flex justify="center" align="center" size="small">
              <span>{{ frontEndStore.MASK_INFO(item.ip) }}</span>
              <n-tooltip
                v-if="
                  hasConfiguredIpv4Mismatch(
                    item.ip,
                    Array.from(arp_ip_map.get(item.ip)?.macs || [])[0],
                  )
                "
                trigger="hover"
              >
                <template #trigger>
                  <n-tag size="small" type="warning" :bordered="false">
                    IP
                  </n-tag>
                </template>
                <div>{{ t("device.lease_ip_mismatch") }}</div>
                <div>
                  {{ t("device.observed_ip") }}:
                  {{ frontEndStore.MASK_INFO(item.ip) }}
                </div>
                <div>
                  {{ t("device.configured_ip") }}:
                  {{
                    frontEndStore.MASK_INFO(
                      getConfiguredIpv4(
                        Array.from(arp_ip_map.get(item.ip)?.macs || [])[0],
                      ) || "",
                    )
                  }}
                </div>
              </n-tooltip>
            </n-flex>
          </td>
          <td class="not-assign-item">
            {{ t("dhcp_v4.assigned.unknown") }}
          </td>
          <td class="not-assign-item">
            {{ t("dhcp_v4.assigned.unknown") }}
          </td>
          <td class="not-assign-item">
            <OnlineStatus
              :ip_status="arp_ip_map.get(item.ip)?.ip_status"
            ></OnlineStatus>
            <!-- {{ arp_ip_map.get(item.ip) }} -->
          </td>
          <td class="not-assign-item">
            <n-button
              size="tiny"
              quaternary
              circle
              @click="quickBind(item.ip)"
              :disabled="!arp_ip_map.get(item.ip)?.macs.size"
            >
              <template #icon>
                <n-icon>
                  <Edit
                    v-if="
                      enrolledDeviceStore.GET_BINDING_ID(
                        Array.from(arp_ip_map.get(item.ip)?.macs || [])[0],
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
  </n-card>

  <EnrolledDeviceEditModal
    v-model:show="showQuickBind"
    :rule_id="bindRuleId"
    :initial-values="initialValues"
    @refresh="emit('refresh')"
  />
</template>
<style scoped>
.assign-head {
  text-align: center;
}
.assign-item {
  text-align: center;
}
.not-assign-item {
  text-align: center;
  color: #f2c97d;
}
</style>
