<script setup lang="ts">
import { get_docker_container_summarys } from "@/api/docker";
import { useWanLinkStore } from "@/stores/wan_link";
import type {
  FlowTarget,
  WeightedFlowTarget,
} from "@landscape-router/types/api/schemas";
import { computed, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";

const { t } = useI18n();

const target_rules = defineModel<WeightedFlowTarget[]>("target_rules", {
  required: true,
});

const wanLinkStore = useWanLinkStore();
const docker_containers = ref<any[]>([]);

onMounted(async () => {
  await refresh_wan_ifaces();
});

async function refresh_wan_ifaces() {
  await wanLinkStore.ensureLoaded();
  docker_containers.value = await get_docker_container_summarys();
}

const iface_wan_options = computed(() =>
  wanLinkStore.options.map((link) => ({
    label: link.label,
    value: link.value,
  })),
);

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

function onCreate(): WeightedFlowTarget {
  return {
    target: { t: "interface", name: "", link_id: undefined },
    weight: 1,
  };
}

function target_type_option(): any[] {
  return [
    {
      label: t("flow.target_rule.type_wan"),
      value: "interface",
    },
    {
      label: t("flow.target_rule.type_docker"),
      value: "netns",
    },
  ];
}

function handleUpdateValue(value: FlowTarget["t"], index: number) {
  const weight = target_rules.value[index]?.weight ?? 1;
  if (value == FlowTargetEnum.Interface) {
    target_rules.value[index] = {
      target: {
        t: FlowTargetEnum.Interface,
        name: "",
        link_id: undefined,
      },
      weight,
    };
  } else {
    target_rules.value[index] = {
      target: {
        t: FlowTargetEnum.NetNS,
        container_name: "",
      },
      weight,
    };
  }
}

function handleLinkChange(linkId: string, index: number) {
  const link = wanLinkStore.options.find((item) => item.value === linkId);
  const target = target_rules.value[index]?.target;
  if (target && target.t === "interface") {
    target.name = link?.net_iface ?? "";
  }
}
</script>

<template>
  <n-dynamic-input
    :min="0"
    :max="16"
    v-model:value="target_rules"
    :on-create="onCreate"
  >
    <template #create-button-default>
      {{ t("flow.target_rule.add_target_rule") }}
    </template>
    <template #default="{ value, index }">
      <n-input-group>
        <n-select
          :style="{ width: '24%' }"
          v-model:value="value.target.t"
          @update:value="handleUpdateValue($event, index)"
          :options="target_type_option()"
        />

        <n-select
          v-if="value.target.t == 'interface'"
          v-model:value="value.target.link_id"
          @update:value="handleLinkChange($event, index)"
          :style="{ width: '56%' }"
          :options="iface_wan_options"
          :placeholder="t('flow.target_rule.iface_placeholder')"
        />
        <n-select
          v-else-if="value.target.t == 'netns'"
          v-model:value="value.target.container_name"
          :style="{ width: '56%' }"
          :options="docker_options"
          :placeholder="t('flow.target_rule.container_placeholder')"
        />

        <n-input-number
          v-model:value="value.weight"
          :style="{ width: '20%' }"
          :min="0"
          :step="1"
          :show-button="false"
          :placeholder="t('flow.target_rule.weight_placeholder')"
        />
      </n-input-group>
    </template>
  </n-dynamic-input>
</template>
