<script setup lang="ts">
import { update_iface_pppd_config } from "@/api/service_pppd";
import { PPPDServiceConfig } from "@/lib/pppd";
import { computed, ref } from "vue";
import type { SelectOption } from "naive-ui";
import { useFrontEndStore } from "@/stores/front_end_config";
import { useI18n } from "vue-i18n";

const pluginOptions: SelectOption[] = [
  { label: "rp-pppoe.so", value: "rp_pppoe" },
  { label: "pppoe.so", value: "pppoe" },
];

const frontEndStore = useFrontEndStore();
const { t } = useI18n();
const show = defineModel<boolean>("show", { required: true });
const props = defineProps<{
  attach_iface_name: string;
  origin_value: PPPDServiceConfig | undefined;
}>();

// const origin_value = defineModel<PPPDServiceConfig>("config", {
//   required: true,
// });

const emit = defineEmits(["refresh"]);
const value = ref<PPPDServiceConfig>(
  new PPPDServiceConfig({
    attach_iface_name: props.attach_iface_name,
  }),
);

const isModified = computed(() => {
  return JSON.stringify(value.value) !== JSON.stringify(props.origin_value);
});

async function init_conf_value() {
  value.value = new PPPDServiceConfig(
    props.origin_value
      ? props.origin_value
      : {
          attach_iface_name: props.attach_iface_name,
        },
  );
}

async function confirm_config() {
  if (isModified) {
    if (!value.value.iface_name || value.value.iface_name.trim() === "") {
      window.$message.error(t("pppd_editor.iface_required"));
      return;
    }
    await update_iface_pppd_config(value.value);
    show.value = false;
    emit("refresh");
  }
}
</script>
<template>
  <n-modal
    v-model:show="show"
    preset="card"
    style="width: 600px"
    :title="t('pppd_editor.title')"
    @after-enter="init_conf_value"
  >
    <!-- <template #header-extra> 噢! </template> -->
    <!-- {{ origin_value }} -->

    <n-form style="flex: 1" ref="formRef" :model="value" :cols="4">
      <n-grid :cols="5">
        <n-form-item-gi :label="t('pppd_editor.enable')" :span="1">
          <n-switch v-model:value="value.enable">
            <template #checked> {{ t("pppd_editor.enabled_yes") }} </template>
            <template #unchecked> {{ t("pppd_editor.enabled_no") }} </template>
          </n-switch>
        </n-form-item-gi>

        <n-form-item-gi :span="2" :label="t('pppd_editor.default_route')">
          <n-switch v-model:value="value.pppd_config.default_route">
            <template #checked> {{ t("pppd_editor.enabled_yes") }} </template>
            <template #unchecked> {{ t("pppd_editor.enabled_no") }} </template>
          </n-switch>
        </n-form-item-gi>

        <n-form-item-gi :label="t('pppd_editor.ppp_iface_name')" :span="2">
          <n-input v-model:value="value.iface_name" clearable />
        </n-form-item-gi>
      </n-grid>

      <n-form-item :label="t('pppd_editor.username')">
        <n-input
          :type="frontEndStore.presentation_mode ? 'password' : 'text'"
          show-password-on="click"
          v-model:value="value.pppd_config.peer_id"
        />
      </n-form-item>

      <n-form-item :label="t('pppd_editor.password')">
        <n-input
          :type="frontEndStore.presentation_mode ? 'password' : 'text'"
          show-password-on="click"
          v-model:value="value.pppd_config.password"
        />
      </n-form-item>

      <n-form-item>
        <template #label>
          <Notice>
            {{ t("pppd_editor.ac_name") }}
            <template #msg> {{ t("pppd_editor.ac_name_tip") }} </template>
          </Notice>
        </template>
        <n-input
          :type="frontEndStore.presentation_mode ? 'password' : 'text'"
          show-password-on="click"
          v-model:value="value.pppd_config.ac"
        />
      </n-form-item>

      <n-form-item :label="t('pppd_editor.plugin')">
        <n-select
          v-model:value="value.pppd_config.plugin"
          :options="pluginOptions"
        />
      </n-form-item>
    </n-form>
    <template #footer>
      <n-flex justify="space-between">
        <n-button @click="show = false">{{ t("pppd_editor.cancel") }}</n-button>
        <n-button
          @click="confirm_config()"
          type="success"
          :disabled="!isModified"
        >
          {{ t("pppd_editor.confirm") }}
        </n-button>
      </n-flex>
    </template>
  </n-modal>
</template>
