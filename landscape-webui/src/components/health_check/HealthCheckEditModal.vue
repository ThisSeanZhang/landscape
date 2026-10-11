<script setup lang="ts">
import { ref } from "vue";
import { useI18n } from "vue-i18n";
import { useMessage, type FormInst, type FormRules } from "naive-ui";
import { HelpCircleOutline } from "@vicons/ionicons5";
import ConfigModal from "@/components/common/ConfigModal.vue";
import { create_wan_link, update_wan_link } from "@/api/service_wan_link";
import { is_ipv4 } from "@/lib/common";
import {
  default_ethernet_link,
  MAX_HEALTH_TARGETS,
  WanLink,
} from "@/lib/wan_link";
import { useWanLinkStore } from "@/stores/wan_link";

const wanLinkStore = useWanLinkStore();
const { t } = useI18n();
const message = useMessage();
const show_model = defineModel<boolean>("show", { required: true });
const emit = defineEmits(["refresh"]);

const iface_info = defineProps<{
  iface_name: string;
}>();

const link = ref<WanLink>(default_ethernet_link(iface_info.iface_name));
const form_ref = ref<FormInst | null>(null);

async function on_modal_enter() {
  await wanLinkStore.UPDATE_INFO();
  link.value =
    wanLinkStore.RESOLVE_NODE_LINK(iface_info.iface_name).value ??
    default_ethernet_link(iface_info.iface_name);
}

const form_rules: FormRules = {
  "probe.targets": {
    trigger: ["blur", "input"],
    validator: () => {
      const health = link.value.health_check;
      if (health.probe.targets.some((target) => !is_ipv4(target))) {
        return new Error(t("network.health_check.invalid_target"));
      }
      if (
        health.enable &&
        health.probe.targets.length === 0 &&
        !health.probe.probe_gateway
      ) {
        return new Error(t("network.health_check.nothing_to_probe"));
      }
      return true;
    },
  },
  reliability: {
    trigger: ["blur", "input"],
    validator: (_rule, value: number) => {
      if (value < 1 || value > 100) {
        return new Error(t("network.health_check.reliability_range"));
      }
      return true;
    },
  },
};

async function save_config() {
  try {
    await form_ref.value?.validate();
  } catch (_err) {
    return;
  }
  try {
    if (link.value.is_new()) {
      await create_wan_link(link.value);
    } else {
      await update_wan_link(link.value);
    }
  } catch (err: any) {
    message.error(err?.message || t("network.health_check.save_failed"));
    return;
  }
  await wanLinkStore.UPDATE_INFO();
  emit("refresh");
  show_model.value = false;
}
</script>

<template>
  <ConfigModal
    v-model:show="show_model"
    v-model:enabled="link.health_check.enable"
    :title="t('network.health_check.title')"
    width="600px"
    @after-enter="on_modal_enter"
  >
    <n-form ref="form_ref" :model="link.health_check" :rules="form_rules">
      <n-form-item path="probe.targets">
        <template #label>
          {{ t("network.health_check.targets") }}
          <n-tooltip trigger="hover" style="cursor: help">
            <template #trigger>
              <n-icon size="14" color="#888">
                <HelpCircleOutline />
              </n-icon>
            </template>
            {{ t("network.health_check.targets_tooltip") }}
          </n-tooltip>
        </template>
        <n-dynamic-input
          v-model:value="link.health_check.probe.targets"
          :on-create="() => ''"
          :max="MAX_HEALTH_TARGETS"
          :placeholder="t('network.health_check.target_placeholder')"
        >
          <template #create-button-default>
            {{ t("network.health_check.add_target") }}
          </template>
        </n-dynamic-input>
      </n-form-item>
      <n-form-item :label="t('network.health_check.probe_gateway')">
        <n-checkbox v-model:checked="link.health_check.probe.probe_gateway">
          {{ t("network.health_check.probe_gateway_hint") }}
        </n-checkbox>
      </n-form-item>
      <n-grid :cols="2" :x-gap="12">
        <n-form-item-gi path="interval_secs">
          <template #label>
            {{ t("network.health_check.interval_secs") }}
            <n-tooltip trigger="hover" style="cursor: help">
              <template #trigger>
                <n-icon size="14" color="#888">
                  <HelpCircleOutline />
                </n-icon>
              </template>
              {{ t("network.health_check.interval_tooltip") }}
            </n-tooltip>
          </template>
          <n-input-number
            v-model:value="link.health_check.interval_secs"
            style="width: 100%"
            :min="1"
            :max="65535"
          />
        </n-form-item-gi>
        <n-form-item-gi path="timeout_ms">
          <template #label>
            {{ t("network.health_check.timeout_ms") }}
            <n-tooltip trigger="hover" style="cursor: help">
              <template #trigger>
                <n-icon size="14" color="#888">
                  <HelpCircleOutline />
                </n-icon>
              </template>
              {{ t("network.health_check.timeout_tooltip") }}
            </n-tooltip>
          </template>
          <n-input-number
            v-model:value="link.health_check.timeout_ms"
            style="width: 100%"
            :min="1"
            :max="10000"
          />
        </n-form-item-gi>
        <n-form-item-gi path="failure_threshold">
          <template #label>
            {{ t("network.health_check.failure_threshold") }}
            <n-tooltip trigger="hover" style="cursor: help">
              <template #trigger>
                <n-icon size="14" color="#888">
                  <HelpCircleOutline />
                </n-icon>
              </template>
              {{ t("network.health_check.failure_threshold_tooltip") }}
            </n-tooltip>
          </template>
          <n-input-number
            v-model:value="link.health_check.failure_threshold"
            style="width: 100%"
            :min="1"
            :max="100"
          />
        </n-form-item-gi>
        <n-form-item-gi path="recovery_threshold">
          <template #label>
            {{ t("network.health_check.recovery_threshold") }}
            <n-tooltip trigger="hover" style="cursor: help">
              <template #trigger>
                <n-icon size="14" color="#888">
                  <HelpCircleOutline />
                </n-icon>
              </template>
              {{ t("network.health_check.recovery_threshold_tooltip") }}
            </n-tooltip>
          </template>
          <n-input-number
            v-model:value="link.health_check.recovery_threshold"
            style="width: 100%"
            :min="1"
            :max="100"
          />
        </n-form-item-gi>
        <n-form-item-gi path="reliability">
          <template #label>
            {{ t("network.health_check.reliability") }}
            <n-tooltip trigger="hover" style="cursor: help">
              <template #trigger>
                <n-icon size="14" color="#888">
                  <HelpCircleOutline />
                </n-icon>
              </template>
              {{ t("network.health_check.reliability_tooltip") }}
            </n-tooltip>
          </template>
          <n-input-number
            v-model:value="link.health_check.reliability"
            style="width: 100%"
            :min="1"
            :max="100"
          />
        </n-form-item-gi>
      </n-grid>
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
