<script setup lang="ts">
import { computed } from "vue";

import { HelpFilled } from "@vicons/carbon";
import { LDIAPrefix } from "@/rust_bindings/common/ipv6_pd";
import { useFrontEndStore } from "@/stores/front_end_config";

const frontEndStore = useFrontEndStore();

interface Props {
  config: LDIAPrefix;
  iface_name: string;
  show_action?: boolean;
}

const props = withDefaults(defineProps<Props>(), {
  show_action: false,
});

const emit = defineEmits(["refresh"]);

async function refresh() {
  emit("refresh");
}
const status = computed(() => {
  if (
    props.config.last_update_time + props.config.valid_lifetime * 1000 >
    new Date().getTime()
  ) {
    return true;
  }

  return false;
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
      <StatusTitle :enable="status" :remark="props.iface_name"></StatusTitle>
    </template>
    <!-- {{ config }} -->
    <n-descriptions style="flex: 1" bordered label-placement="top" :column="3">
      <n-descriptions-item>
        <template #label>
          <n-flex align="center">
            <span> IP 首选时间 </span>
            <n-popover trigger="hover">
              <template #trigger>
                <n-button text>
                  <template #icon>
                    <n-icon><HelpFilled /></n-icon>
                  </template>
                </n-button>
              </template>
              <span>当有多个 IP 时, 作为首选IP的时间</span>
            </n-popover>
          </n-flex>
        </template>
        {{ config.preferred_lifetime }}s
      </n-descriptions-item>
      <n-descriptions-item>
        <template #label>
          <n-flex align="center">
            <span> IP 有效时间 </span>
            <n-popover trigger="hover">
              <template #trigger>
                <n-button text>
                  <template #icon>
                    <n-icon><HelpFilled /></n-icon>
                  </template>
                </n-button>
              </template>
              <span>从获得到丢弃该 IP 的时间, 包含首选时间</span>
            </n-popover>
          </n-flex>
        </template>
        {{ config.valid_lifetime }}s
      </n-descriptions-item>
      <n-descriptions-item label="前缀">
        {{ frontEndStore.MASK_INFO(config.prefix_ip) }}/{{ config.prefix_len }}
      </n-descriptions-item>
      <n-descriptions-item :span="3">
        <template #label>
          <n-flex align="center">
            <span>最近更新时间</span>
            <n-popover trigger="hover">
              <template #trigger>
                <n-button text>
                  <template #icon>
                    <n-icon><HelpFilled /></n-icon>
                  </template>
                </n-button>
              </template>
              <span>DHCPv6 Client 得到前缀的时间</span>
            </n-popover>
          </n-flex>
        </template>
        <n-time :time="config.last_update_time" format="yyyy-MM-dd hh:mm:ss" />
      </n-descriptions-item>
    </n-descriptions>
  </n-card>
</template>
