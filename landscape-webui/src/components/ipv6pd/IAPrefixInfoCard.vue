<script setup lang="ts">
import { computed } from "vue";
import { useI18n } from "vue-i18n";

import { HelpFilled } from "@vicons/carbon";
import type { IPV6PDPrefixStatus } from "@/api/service_ipv6pd";
import { useFrontEndStore } from "@/stores/front_end_config";
import { usePreferenceStore } from "@/stores/preference";
const prefStore = usePreferenceStore();
const { t } = useI18n();

const frontEndStore = useFrontEndStore();

interface Props {
  prefix_status: IPV6PDPrefixStatus;
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
const actualPrefix = computed(() => props.prefix_status.actual_prefix);
// WAN PD owns the acquired-prefix vs WAN-expectation verdict. LAN snapshot
// compatibility is intentionally reported by the LAN prefix-group UI instead.
const status = computed(() => {
  if (
    actualPrefix.value &&
    props.prefix_status.meets_expected_pd_len === true
  ) {
    if (
      actualPrefix.value.last_update_time +
        actualPrefix.value.valid_lifetime * 1000 >
      new Date().getTime()
    ) {
      return true;
    }
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
    <n-descriptions style="flex: 1" bordered label-placement="top" :column="3">
      <n-descriptions-item
        :label="t('lan_ipv6.prefix_info.expected_prefix_len')"
      >
        /{{ prefix_status.expected_pd_len }}
      </n-descriptions-item>
      <n-descriptions-item :label="t('lan_ipv6.prefix_info.prefix')">
        <template v-if="actualPrefix">
          {{ frontEndStore.MASK_INFO(actualPrefix.prefix_ip) }}/{{
            actualPrefix.prefix_len
          }}
        </template>
        <n-text v-else depth="3">
          {{ t("lan_ipv6.prefix_info.no_prefix_yet") }}
        </n-text>
      </n-descriptions-item>
      <n-descriptions-item :label="t('lan_ipv6.prefix_info.prefix_len_status')">
        <n-tag
          v-if="prefix_status.meets_expected_pd_len === true"
          :bordered="false"
          type="success"
        >
          {{ t("lan_ipv6.prefix_info.prefix_len_matches") }}
        </n-tag>
        <n-tag
          v-else-if="prefix_status.meets_expected_pd_len === false"
          :bordered="false"
          type="warning"
        >
          {{ t("lan_ipv6.prefix_info.prefix_len_mismatch") }}
        </n-tag>
        <n-tag v-else :bordered="false">
          {{ t("lan_ipv6.prefix_info.prefix_len_waiting") }}
        </n-tag>
      </n-descriptions-item>
      <n-descriptions-item v-if="actualPrefix">
        <template #label>
          <n-flex align="center">
            <span> {{ t("lan_ipv6.prefix_info.ip_preferred_time") }} </span>
            <n-popover trigger="hover">
              <template #trigger>
                <n-button text>
                  <template #icon>
                    <n-icon><HelpFilled /></n-icon>
                  </template>
                </n-button>
              </template>
              <span>{{
                t("lan_ipv6.prefix_info.ip_preferred_time_desc")
              }}</span>
            </n-popover>
          </n-flex>
        </template>
        {{ actualPrefix.preferred_lifetime }}s
      </n-descriptions-item>
      <n-descriptions-item v-if="actualPrefix">
        <template #label>
          <n-flex align="center">
            <span> {{ t("lan_ipv6.prefix_info.ip_valid_time") }} </span>
            <n-popover trigger="hover">
              <template #trigger>
                <n-button text>
                  <template #icon>
                    <n-icon><HelpFilled /></n-icon>
                  </template>
                </n-button>
              </template>
              <span>{{ t("lan_ipv6.prefix_info.ip_valid_time_desc") }}</span>
            </n-popover>
          </n-flex>
        </template>
        {{ actualPrefix.valid_lifetime }}s
      </n-descriptions-item>
      <n-descriptions-item v-if="actualPrefix">
        <template #label>
          <n-flex align="center">
            <span>{{ t("lan_ipv6.prefix_info.last_update") }}</span>
            <n-popover trigger="hover">
              <template #trigger>
                <n-button text>
                  <template #icon>
                    <n-icon><HelpFilled /></n-icon>
                  </template>
                </n-button>
              </template>
              <span>{{
                t("lan_ipv6.prefix_info.dhcpv6_client_prefix_time")
              }}</span>
            </n-popover>
          </n-flex>
        </template>
        <n-time
          :time="actualPrefix.last_update_time"
          format="yyyy-MM-dd hh:mm:ss"
          :time-zone="prefStore.timezone"
        />
      </n-descriptions-item>
    </n-descriptions>
  </n-card>
</template>
