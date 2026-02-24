<script setup lang="ts">
import { computed } from "vue";

import { HelpFilled, Time } from "@vicons/carbon";
import type { IPv6NAInfo } from "@/api/service_icmpv6ra";
import { useFrontEndStore } from "@/stores/front_end_config";
import { usePreferenceStore } from "@/stores/preference";
const prefStore = usePreferenceStore();

const frontEndStore = useFrontEndStore();

interface Props {
  config: IPv6NAInfo | null;
  iface_name: string;
  show_action?: boolean;
}
interface TableItem {
  ip: string;
  mac: string;
  active: number;
  stale: boolean;
}

const props = withDefaults(defineProps<Props>(), {
  show_action: false,
});

const emit = defineEmits(["refresh"]);

async function refresh() {
  emit("refresh");
}

const info = computed(() => {
  let result: TableItem[] = [];
  if (props.config?.offered_ips) {
    const time = new Date().getTime();
    for (const value of Object.values(props.config?.offered_ips ?? {})) {
      if (!value) continue;
      const each_time =
        value?.relative_active_time * 1000 + props.config.boot_time;
      // console.log(time);
      // console.log(each_time);
      // console.log(time - each_time);
      result.push({
        ip: value.ip,
        mac: value.mac as unknown as string,
        active: each_time,
        stale: time - each_time < 30 * 1000,
      });
    }
  }
  return result;
});
</script>

<template>
  <n-card
    style="min-height: 224px"
    content-style="display: flex"
    size="small"
    :hoverable="true"
  >
    <template #header>
      {{ props.iface_name }}
    </template>
    <!-- {{ config }} -->
    <n-table v-if="info.length > 0" :bordered="true" size="small" striped>
      <thead>
        <tr>
          <th>IPv6</th>
          <th>Mac</th>
          <th>时间</th>
          <th>状态</th>
        </tr>
      </thead>

      <tbody>
        <tr v-for="value in info">
          <td>
            {{ frontEndStore.MASK_INFO(value.ip) }}
          </td>
          <td>{{ frontEndStore.MASK_INFO(value.mac) }}</td>
          <td>
            <n-time
              :time="value.active"
              :time-zone="prefStore.timezone"
            ></n-time>
          </td>
          <td>
            <n-tag v-if="value.stale" :bordered="false" type="success">
              ACTIVE
            </n-tag>
            <n-tag v-else :bordered="false" type="warning"> STALE </n-tag>
          </td>
        </tr>
      </tbody>
    </n-table>
    <n-flex
      align="center"
      justify="center"
      style="height: 190px; flex: 1"
      v-else
    >
      <n-empty description="IPv6 邻居数量未知"> </n-empty>
    </n-flex>
  </n-card>
</template>
