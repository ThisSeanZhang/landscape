<script setup lang="ts">
import { get_docker_container_summarys } from "@/api/docker";
import { get_wan_ifaces } from "@/api/iface";
import { get_all_iface_pppd_config } from "@/api/service_pppd";
import type { FlowTarget } from "@landscape-router/types/api/schemas";
import { useFrontEndStore } from "@/stores/front_end_config";
import { computed, onMounted, ref } from "vue";

const frontEndStore = useFrontEndStore();

const target_rules = defineModel<FlowTarget[]>("target_rules", {
  required: true,
});

const iface_wans = ref<any[]>([]);
const docker_containers = ref<any[]>([]);
const pppd_services = ref<any[]>([]);

onMounted(async () => {
  await refresh_wan_ifaces();
});

async function refresh_wan_ifaces() {
  iface_wans.value = await get_wan_ifaces();
  docker_containers.value = await get_docker_container_summarys();
  pppd_services.value = await get_all_iface_pppd_config();
}

const iface_wan_options = computed(() => {
  let iface = iface_wans.value.map((e) => ({
    label: e.name,
    value: e.name,
  }));
  let pppd_iface = pppd_services.value.map((e) => ({
    label: e.iface_name,
    value: e.iface_name,
  }));
  return [...iface, ...pppd_iface];
});

const docker_options = computed(() =>
  docker_containers.value.map((e) => {
    let name = e.Names[0] ?? "";
    if (name.startsWith("/")) {
      name = name.slice(1);
    }
    return {
      label: name,
      value: name,
    };
  }),
);

enum FlowTargetEnum {
  Interface = "interface",
  NetNS = "netns",
}

function onCreate(): FlowTarget {
  return { t: "interface", name: "" };
}

function target_type_option(): any[] {
  return [
    {
      label: "WAN 网卡",
      value: "interface",
    },
    {
      label: "Docker",
      value: "netns",
    },
  ];
}

function handleUpdateValue(value: FlowTarget, index: number) {
  if (value.t == FlowTargetEnum.Interface) {
    target_rules.value[index] = {
      t: FlowTargetEnum.Interface,
      name: "",
    };
  } else {
    target_rules.value[index] = { t: FlowTargetEnum.NetNS, container_name: "" };
  }
}
</script>

<template>
  <!-- {{ docker_options }} -->
  <!-- {{ docker_containers }} -->
  <n-dynamic-input
    :min="0"
    :max="1"
    v-model:value="target_rules"
    :on-create="onCreate"
  >
    <template #create-button-default> 增加一条出口规则 </template>
    <template #default="{ value, index }">
      <n-input-group>
        <n-select
          :style="{ width: '33%' }"
          v-model:value="value.t"
          @update:value="handleUpdateValue(value, index)"
          :options="target_type_option()"
        />

        <n-select
          v-if="value.t == 'interface'"
          v-model:value="value.name"
          :style="{ width: '66%' }"
          :options="iface_wan_options"
          placeholder="网卡名称"
        />
        <n-select
          v-else-if="value.t == 'netns'"
          v-model:value="value.container_name"
          :style="{ width: '66%' }"
          :options="docker_options"
          placeholder="容器名称"
        />
      </n-input-group>
    </template>
  </n-dynamic-input>
</template>
