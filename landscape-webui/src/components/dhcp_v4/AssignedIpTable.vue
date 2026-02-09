<script lang="ts" setup>
import { sleep } from "@/lib/util";
import {
  ArpScanInfo,
  DHCPv4OfferInfo,
  DHCPv4OfferInfoItem,
} from "landscape-types/common/dhcp_v4_server";
import { CountdownInst } from "naive-ui";
import { computed, nextTick, ref, watch } from "vue";

import { useFrontEndStore } from "@/stores/front_end_config";
import { usePreferenceStore } from "@/stores/preference";
const prefStore = usePreferenceStore();
import { mask_string } from "@/lib/common";
import { Key } from "@vicons/tabler";
import { AddAlt, Edit } from "@vicons/carbon";
import { useMacBindingStore } from "@/stores/mac_binding";
import MacBindingEditModal from "@/components/device/MacBindingEditModal.vue";

const frontEndStore = useFrontEndStore();
const macBindingStore = useMacBindingStore();
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

function caculate_time(item: DHCPv4OfferInfoItem): number {
  const expire_time =
    (item.relative_active_time + item.expire_time) * 1000 +
    props.info.boot_time;
  return expire_time - new Date().getTime();
}

function request_time(item: DHCPv4OfferInfoItem): number {
  return item.relative_active_time * 1000 + props.info.boot_time;
}

const show_item = computed(() => {
  let reuslt = [];
  for (const each of props.info.offered_ips) {
    reuslt.push({
      real_request_time: request_time(each),
      real_expire_time: caculate_time(each),
      ...each,
    });
  }
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
        arr.macs.add(item.mac);
      });
    });
  }

  return map;
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

  const existingId = macBindingStore.GET_BINDING_ID(targetMac);
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
          <th class="assign-head" style="width: 20%">主机名</th>
          <th class="assign-head">
            <Notice>
              Mac 地址
              <template #msg>
                ARP 扫描出的 IP 可能会出现 ARP 代应答 <br />
                导致 IP 不同 Mac 却重复的情况
              </template>
            </Notice>
          </th>
          <th class="assign-head">分配 IP</th>
          <th class="assign-head">最近一次请求时间</th>
          <th class="assign-head">
            <Notice>
              剩余租期时间 (s) <template #msg>到期时间</template>
            </Notice>
          </th>
          <th class="assign-head" style="width: 168px">
            <Notice>
              24 小时在线情况
              <template #msg>
                最后一个是最近一小时检查时是否在线 <br />
                定期扫描, 所以新分配的 IP 可能最近一小时显示为不在线
              </template>
            </Notice>
          </th>
          <th class="assign-head" style="width: 80px">操作</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="item in show_item">
          <td class="assign-item">
            {{
              macBindingStore.GET_NAME_WITH_FALLBACK(item.mac, item.hostname)
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
            {{ frontEndStore.MASK_INFO(item.ip) }}
          </td>

          <td class="assign-item">
            <n-time
              :time="item.real_request_time"
              :time-zone="prefStore.timezone"
            ></n-time>
          </td>
          <td class="assign-item">
            <!-- {{ item.real_expire_time }} -->
            <n-flex justify="center" v-if="item.is_static">静态分配</n-flex>
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
                  <Edit v-if="macBindingStore.GET_BINDING_ID(item.mac)" />
                  <AddAlt v-else />
                </n-icon>
              </template>
            </n-button>
          </td>
        </tr>

        <tr v-for="item in not_current_round_ips">
          <td class="not-assign-item">未知</td>
          <td class="not-assign-item">
            <DHCPMacExhibit :macs="arp_ip_map.get(item.ip)?.macs">
            </DHCPMacExhibit>
          </td>
          <td class="not-assign-item">
            {{ frontEndStore.MASK_INFO(item.ip) }}
          </td>
          <td class="not-assign-item">未知</td>
          <td class="not-assign-item">未知</td>
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
                      macBindingStore.GET_BINDING_ID(
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

  <MacBindingEditModal
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
