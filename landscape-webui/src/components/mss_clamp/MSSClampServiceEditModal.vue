<script setup lang="ts">
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";
import ConfigModal from "@/components/common/ConfigModal.vue";
import { create_wan_link, update_wan_link } from "@/api/service_wan_link";
import { default_ethernet_link, WanLink } from "@/lib/wan_link";
import { useWanLinkStore } from "@/stores/wan_link";

const wanLinkStore = useWanLinkStore();
const { t } = useI18n();
const show_model = defineModel<boolean>("show", { required: true });
const emit = defineEmits(["refresh"]);

const iface_info = defineProps<{
  iface_name: string;
}>();

const link = ref<WanLink>(default_ethernet_link(iface_info.iface_name));

async function on_modal_enter() {
  await wanLinkStore.UPDATE_INFO();
  link.value =
    wanLinkStore.RESOLVE_NODE_LINK(iface_info.iface_name).value ??
    default_ethernet_link(iface_info.iface_name);
}

async function save_config() {
  if (link.value.is_new()) {
    await create_wan_link(link.value);
  } else {
    await update_wan_link(link.value);
  }
  await wanLinkStore.UPDATE_INFO();
  emit("refresh");
  show_model.value = false;
}
</script>

<template>
  <ConfigModal
    v-model:show="show_model"
    v-model:enabled="link.mss.enable"
    :title="t('network.mss_clamp.title')"
    width="600px"
    @after-enter="on_modal_enter"
  >
    <n-form :model="link.mss">
      <n-form-item :label="t('network.mss_clamp.clamp_value')">
        <n-input-number
          v-model:value="link.mss.clamp_size"
          :show-button="false"
          style="flex: 1"
          min="0"
          max="65535"
          placeholder=""
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
