<script lang="ts" setup>
import { sleep } from "@/lib/util";
import {
  DHCPv4OfferInfo,
  DHCPv4OfferInfoItem,
} from "@/rust_bindings/common/dhcp_v4_server";
import { CountdownInst } from "naive-ui";
import { computed, nextTick, ref, watch } from "vue";

import { useFrontEndStore } from "@/stores/front_end_config";
import { mask_string } from "@/lib/common";

const frontEndStore = useFrontEndStore();
const emit = defineEmits(["refresh"]);
type Props = {
  info: DHCPv4OfferInfo;
  iface_name: string;
};

const props = withDefaults(defineProps<Props>(), {});

function caculate_time(item: DHCPv4OfferInfoItem): number {
  const expire_time =
    (item.relative_active_time + item.expire_time) * 1000 +
    props.info.boot_time;
  return expire_time - new Date().getTime();
}

const show_item = computed(() => {
  let reuslt = [];
  for (const each of props.info.offered_ips) {
    reuslt.push({
      real_expire_time: caculate_time(each),
      ...each,
    });
  }
  return reuslt;
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
</script>

<template>
  <!-- {{ info }} -->
  <n-card size="small" :title="iface_name">
    <n-table v-if="info" :bordered="true" striped>
      <thead>
        <tr>
          <th style="width: 33%">Mac 地址</th>
          <th style="width: 33%">分配 IP</th>
          <th style="width: 33%">分配租期时间 (s)</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="item in show_item">
          <td>
            {{
              frontEndStore.presentation_mode ? mask_string(item.mac) : item.mac
            }}
          </td>
          <td>
            {{
              frontEndStore.presentation_mode ? mask_string(item.ip) : item.ip
            }}
          </td>
          <td>
            <!-- {{ item.real_expire_time }} -->
            <n-flex v-if="item.is_static">静态分配</n-flex>
            <n-countdown
              v-else
              ref="countdownRefs"
              @finish="finish"
              :duration="item.real_expire_time"
              :active="true"
            />
          </td>
        </tr>
      </tbody>
    </n-table>
  </n-card>
</template>
