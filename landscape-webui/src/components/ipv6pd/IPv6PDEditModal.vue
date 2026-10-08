<script setup lang="ts">
import { computed, ref } from "vue";
import { useMessage } from "naive-ui";
import { useI18n } from "vue-i18n";
import ConfigModal from "@/components/common/ConfigModal.vue";
import { create_wan_link, update_wan_link } from "@/api/service_wan_link";
import { default_ethernet_link, WanLink } from "@/lib/wan_link";
import { useWanLinkStore } from "@/stores/wan_link";
import { generateValidMAC, formatMacAddress } from "@/lib/util";
import { IfaceZoneType } from "@landscape-router/types/api/schemas";

const wanLinkStore = useWanLinkStore();
const message = useMessage();
const { t } = useI18n();

const show_model = defineModel<boolean>("show", { required: true });
const emit = defineEmits(["refresh"]);

const iface_info = defineProps<{
  iface_name: string;
  mac: string | null;
  zone: IfaceZoneType;
}>();

function default_link(): WanLink {
  const link = default_ethernet_link(iface_info.iface_name);
  link.pd.mac = iface_info.mac ?? generateValidMAC();
  return link;
}

const link = ref<WanLink>(default_link());

async function on_modal_enter() {
  await wanLinkStore.UPDATE_INFO();
  const resolved = wanLinkStore.RESOLVE_NODE_LINK(iface_info.iface_name).value;
  if (resolved === undefined) {
    link.value = default_link();
  } else {
    const next = new WanLink(resolved);
    if (!next.pd.mac || next.pd.mac === "00:00:00:00:00:00") {
      next.pd.mac = iface_info.mac ?? generateValidMAC();
    }
    link.value = next;
  }
}

async function save_config() {
  if (link.value.pd.mac === "" || link.value.pd.mac === undefined) {
    message.warning(t("lan_ipv6.mac_required"));
  } else if (
    !Number.isInteger(link.value.pd.expected_pd_len) ||
    link.value.pd.expected_pd_len < 56 ||
    link.value.pd.expected_pd_len > 64
  ) {
    message.warning(t("lan_ipv6.expected_pd_len_invalid"));
  } else {
    if (link.value.is_new()) {
      await create_wan_link(link.value);
    } else {
      await update_wan_link(link.value);
    }
    await wanLinkStore.UPDATE_INFO();
    emit("refresh");
    show_model.value = false;
  }
}
</script>

<template>
  <ConfigModal
    v-model:show="show_model"
    v-model:enabled="link.pd.enable"
    :title="t('lan_ipv6.ipv6_pd_config')"
    width="600px"
    @after-enter="on_modal_enter"
  >
    <n-form :model="link.pd">
      <n-form-item :label="t('lan_ipv6.mac_hint')">
        <n-input
          :value="link.pd.mac"
          @update:value="(v: string) => (link.pd.mac = formatMacAddress(v))"
        ></n-input>
      </n-form-item>
      <n-form-item :label="t('lan_ipv6.expected_pd_len')">
        <n-input-number
          v-model:value="link.pd.expected_pd_len"
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
