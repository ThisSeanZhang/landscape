<script setup lang="ts">
import { new_ifaces } from "@/api/iface";
import { update_iface_pppd_config } from "@/api/service_pppd";
import { PPPDServiceConfig } from "@/lib/pppd";
import { computed, ref } from "vue";
import type { SelectOption } from "naive-ui";
import ConfigModal from "@/components/common/ConfigModal.vue";
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

const emit = defineEmits(["refresh"]);
const value = ref<PPPDServiceConfig>(
  new PPPDServiceConfig({
    attach_iface_name: props.attach_iface_name,
  }),
);
const isEditing = computed(() => props.origin_value !== undefined);
const existingIfaceNames = ref<string[]>([]);
const PPP_IFACE_NAME_PATTERN = /^[A-Za-z0-9_-]{1,15}$/;

const isModified = computed(() => {
  return JSON.stringify(value.value) !== JSON.stringify(props.origin_value);
});

async function init_conf_value() {
  const iface_infos = (await new_ifaces()) as unknown as {
    managed: Array<{ config: { name: string } }>;
    unmanaged: Array<{ status: { name: string } }>;
  };
  existingIfaceNames.value = [
    ...iface_infos.managed.map((iface) => iface.config.name),
    ...iface_infos.unmanaged.map((iface) => iface.status.name),
  ];
  value.value = new PPPDServiceConfig(
    props.origin_value
      ? props.origin_value
      : {
          attach_iface_name: props.attach_iface_name,
        },
  );
}

async function confirm_config() {
  if (isModified.value) {
    if (!value.value.iface_name || value.value.iface_name.trim() === "") {
      window.$message.error(t("pppoe.editor.iface_required"));
      return;
    }

    if (
      value.value.iface_name !== value.value.iface_name.trim() ||
      !PPP_IFACE_NAME_PATTERN.test(value.value.iface_name)
    ) {
      window.$message.error(t("pppoe.editor.iface_invalid_format"));
      return;
    }

    if (value.value.iface_name === value.value.attach_iface_name) {
      window.$message.error(t("pppoe.editor.iface_same_as_attach"));
      return;
    }

    const hasIfaceConflict = existingIfaceNames.value.includes(
      value.value.iface_name,
    );
    if (
      hasIfaceConflict &&
      value.value.iface_name !== props.origin_value?.iface_name
    ) {
      window.$message.error(t("pppoe.editor.iface_conflict_existing"));
      return;
    }

    await update_iface_pppd_config(value.value, props.origin_value?.iface_name);
    show.value = false;
    emit("refresh");
  }
}
</script>
<template>
  <ConfigModal
    v-model:show="show"
    v-model:enabled="value.enable"
    :title="t('pppoe.editor.title')"
    width="600px"
    @after-enter="init_conf_value"
  >
    <!-- <template #header-extra> 噢! </template> -->
    <!-- {{ origin_value }} -->

    <n-form style="flex: 1" ref="formRef" :model="value" :cols="4">
      <n-grid :cols="5">
        <n-form-item-gi :span="2" :label="t('pppoe.editor.default_route')">
          <n-switch v-model:value="value.pppd_config.default_route">
            <template #checked> {{ t("common.enable") }} </template>
            <template #unchecked> {{ t("common.disable") }} </template>
          </n-switch>
        </n-form-item-gi>

        <n-form-item-gi :label="t('pppoe.editor.ppp_iface_name')" :span="2">
          <n-input
            v-model:value="value.iface_name"
            clearable
            :disabled="isEditing"
          />
        </n-form-item-gi>
      </n-grid>

      <n-form-item :label="t('pppoe.editor.username')">
        <n-input
          :type="frontEndStore.presentation_mode ? 'password' : 'text'"
          show-password-on="click"
          v-model:value="value.pppd_config.peer_id"
        />
      </n-form-item>

      <n-form-item :label="t('pppoe.editor.password')">
        <n-input
          :type="frontEndStore.presentation_mode ? 'password' : 'text'"
          show-password-on="click"
          v-model:value="value.pppd_config.password"
        />
      </n-form-item>

      <n-form-item>
        <template #label>
          <Notice>
            {{ t("pppoe.editor.ac_name") }}
            <template #msg> {{ t("pppoe.editor.ac_name_tip") }} </template>
          </Notice>
        </template>
        <n-input
          :type="frontEndStore.presentation_mode ? 'password' : 'text'"
          show-password-on="click"
          v-model:value="value.pppd_config.ac"
        />
      </n-form-item>

      <n-form-item :label="t('pppoe.editor.plugin')">
        <n-select
          v-model:value="value.pppd_config.plugin"
          :options="pluginOptions"
        />
      </n-form-item>
    </n-form>
    <template #footer>
      <n-flex justify="space-between">
        <n-button @click="show = false">{{ t("common.cancel") }}</n-button>
        <n-button
          @click="confirm_config()"
          type="success"
          :disabled="!isModified"
        >
          {{ t("common.save") }}
        </n-button>
      </n-flex>
    </template>
  </ConfigModal>
</template>
