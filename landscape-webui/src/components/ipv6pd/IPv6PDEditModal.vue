<script setup lang="ts">
import { computed, ref } from "vue";
import { useMessage } from "naive-ui";
import { useI18n } from "vue-i18n";
import ConfigModal from "@/components/common/ConfigModal.vue";
import { IPV6PDConfig, IPV6PDServiceConfig } from "@/lib/ipv6pd";
import {
  get_iface_ipv6pd_config,
  update_ipv6pd_config,
} from "@/api/service_ipv6pd";
import { useIPv6PDStore } from "@/stores/status_ipv6pd";
import { generateValidMAC, formatMacAddress } from "@/lib/util";
import { IfaceZoneType } from "@landscape-router/types/api/schemas";

let ipv6PDStore = useIPv6PDStore();
const message = useMessage();
const { t } = useI18n();

const show_model = defineModel<boolean>("show", { required: true });
const emit = defineEmits(["refresh"]);

const iface_info = defineProps<{
  iface_name: string;
  mac: string | null;
  zone: IfaceZoneType;
}>();

const service_config = ref<IPV6PDServiceConfig>(
  new IPV6PDServiceConfig({
    iface_name: iface_info.iface_name,
    config: new IPV6PDConfig({
      mac: iface_info.mac ?? generateValidMAC(),
    }),
  }),
);

async function on_modal_enter() {
  try {
    let config = await get_iface_ipv6pd_config(iface_info.iface_name);
    console.log(config);
    // iface_service_type.value = config.t;
    service_config.value = config;
  } catch (e) {
    new IPV6PDServiceConfig({
      iface_name: iface_info.iface_name,
      config: new IPV6PDConfig({
        mac: iface_info.mac ?? generateValidMAC(),
      }),
    });
  }
}

async function save_config() {
  if (
    service_config.value.config.mac === "" ||
    service_config.value.config.mac === undefined
  ) {
    message.warning(t("lan_ipv6.mac_required"));
  } else if (
    !Number.isInteger(service_config.value.config.expected_pd_len) ||
    service_config.value.config.expected_pd_len < 56 ||
    service_config.value.config.expected_pd_len > 64
  ) {
    message.warning(t("lan_ipv6.expected_pd_len_invalid"));
  } else {
    let config = await update_ipv6pd_config(service_config.value);
    await ipv6PDStore.UPDATE_INFO();
    show_model.value = false;
  }
}
</script>

<template>
  <ConfigModal
    v-model:show="show_model"
    v-model:enabled="service_config.enable"
    :title="t('lan_ipv6.ipv6_pd_config')"
    width="600px"
    @after-enter="on_modal_enter"
  >
    <!-- {{ service_config }} -->
    <n-form :model="service_config">
      <n-form-item :label="t('lan_ipv6.mac_hint')">
        <n-input
          :value="service_config.config.mac"
          @update:value="
            (v: string) => (service_config.config.mac = formatMacAddress(v))
          "
        ></n-input>
      </n-form-item>
      <n-form-item :label="t('lan_ipv6.expected_pd_len')">
        <n-input-number
          v-model:value="service_config.config.expected_pd_len"
          style="flex: 1"
          :min="56"
          :max="64"
          :step="1"
          :precision="0"
        />
      </n-form-item>
    </n-form>

    <template #footer>
      <n-flex justify="end">
        <n-button round type="primary" @click="save_config">
          {{ t("common.update") }}
        </n-button>
      </n-flex>
    </template>
  </ConfigModal>
</template>
