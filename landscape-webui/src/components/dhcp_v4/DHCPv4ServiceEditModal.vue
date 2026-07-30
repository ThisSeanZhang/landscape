<script setup lang="ts">
import { computed, h, ref } from "vue";
import { NButton, useMessage, useNotification } from "naive-ui";
import { isIPv4 } from "is-ip";
import ConfigModal from "@/components/common/ConfigModal.vue";
import IpEdit from "../IpEdit.vue";
import CustomDhcpOptionEditor from "./options/CustomDhcpOptionEditor.vue";
import IfaceDisableGuardModal from "@/components/iface/IfaceDisableGuardModal.vue";
import { DHCPv4ServiceConfig, get_dhcp_range } from "@/lib/dhcp_v4";
import { useDHCPv4ConfigStore } from "@/stores/status_dhcp_v4";
import {
  get_iface_dhcp_v4_config,
  update_dhcp_v4_config,
} from "@/api/service_dhcp_v4";
import { check_iface_enrolled_devices_validity } from "@/api/enrolled_device";
import { IfaceZoneType } from "@landscape-router/types/api/schemas";
import { useI18n } from "vue-i18n";
import { useRouter } from "vue-router";

const message = useMessage();
const notification = useNotification();
const router = useRouter();
const { t } = useI18n();

const dhcpv4ConfigStore = useDHCPv4ConfigStore();

const show_model = defineModel<boolean>("show", { required: true });
const emit = defineEmits(["refresh"]);

const commit_loading = ref(false);
const optionEditorRef = ref<InstanceType<typeof CustomDhcpOptionEditor>>();
const disable_guard_modal = ref<InstanceType<
  typeof IfaceDisableGuardModal
> | null>(null);
const iface_info = defineProps<{
  iface_name: string;
  zone: IfaceZoneType;
}>();
const origin_service_enable = ref(false);

const service_config = ref<DHCPv4ServiceConfig>(
  new DHCPv4ServiceConfig({
    iface_name: iface_info.iface_name,
  }),
);

async function on_modal_enter() {
  try {
    let config = await get_iface_dhcp_v4_config(iface_info.iface_name);
    console.log(config);
    // iface_service_type.value = config.t;
    service_config.value = config;
    origin_service_enable.value = config.enable;
  } catch (e) {
    service_config.value = new DHCPv4ServiceConfig({
      iface_name: iface_info.iface_name,
    });
    origin_service_enable.value = false;
  }
}

async function save_config() {
  if (!is_valid_dhcp_ipv4_config()) {
    message.error(t("dhcp_v4.invalid_ipv4_check"));
    return;
  }

  if (optionEditorRef.value?.hasDuplicate) {
    message.error(t("dhcp_v4.duplicate_option_check"));
    return;
  }
  if (optionEditorRef.value?.hasInvalid) {
    message.error(t("dhcp_v4.invalid_option_check"));
    return;
  }

  const action = persist_config;
  if (should_check_dhcp_disable() && disable_guard_modal.value) {
    await disable_guard_modal.value.check_and_execute(action);
    return;
  }

  await action();
}

async function persist_config() {
  commit_loading.value = true;
  try {
    await update_dhcp_v4_config(service_config.value);
    await dhcpv4ConfigStore.UPDATE_INFO();
    show_model.value = false;
    origin_service_enable.value = service_config.value.enable;

    // Check enrolled device binding validity after successful save.
    const invalidBindings = await check_iface_enrolled_devices_validity(
      iface_info.iface_name,
    );
    if (invalidBindings.length > 0) {
      notification.warning({
        title: t("device.invalid_bindings_title"),
        content: t("device.invalid_bindings_warning", {
          iface: iface_info.iface_name,
          count: invalidBindings.length,
        }),
        duration: 15000,
        action: () =>
          h(
            NButton,
            {
              text: true,
              type: "primary",
              onClick: () => {
                router.push("/mac-binding");
              },
            },
            {
              default: () => t("device.go_to_manage"),
            },
          ),
      });
    } else {
      message.success(t("dhcp_v4.service.save_success"));
    }
  } catch (e: any) {
    console.log(e);
    message.error(e.response?.data?.msg || t("dhcp_v4.service.save_failed"));
  } finally {
    commit_loading.value = false;
  }
}

function should_check_dhcp_disable() {
  return origin_service_enable.value && !service_config.value.enable;
}

function sync_dhcp_range() {
  const config = service_config.value.config;
  if (
    !isIPv4(config.server_ip_addr) ||
    !is_valid_network_mask(config.network_mask)
  ) {
    return;
  }

  const [start, end] = get_dhcp_range(
    `${config.server_ip_addr}/${config.network_mask}`,
  );
  config.ip_range_start = start;
  config.ip_range_end = end;
}

function is_valid_network_mask(mask: unknown) {
  return Number.isInteger(mask) && Number(mask) >= 0 && Number(mask) <= 30;
}

function is_valid_dhcp_ipv4_config() {
  const config = service_config.value.config;
  return (
    isIPv4(config.server_ip_addr) &&
    isIPv4(config.ip_range_start) &&
    isIPv4(config.ip_range_end ?? "") &&
    is_valid_network_mask(config.network_mask)
  );
}

const server_ip_addr = computed({
  get() {
    return service_config.value.config.server_ip_addr;
  },
  set(new_value) {
    service_config.value.config.server_ip_addr = new_value;
    sync_dhcp_range();
  },
});

const network_mask = computed({
  get() {
    return service_config.value.config.network_mask;
  },
  set(new_value) {
    service_config.value.config.network_mask = new_value;
    sync_dhcp_range();
  },
});
</script>

<template>
  <ConfigModal
    v-model:show="show_model"
    v-model:enabled="service_config.enable"
    :title="t('dhcp_v4.service.title')"
    width="800px"
    max-height="80vh"
    @after-enter="on_modal_enter"
  >
    <div class="dhcp-service-body">
      <n-flex class="dhcp-service-form-wrap">
        <n-form class="dhcp-service-form" :model="service_config">
          <n-alert style="flex: 1" type="warning">
            {{ t("dhcp_v4.service.warning") }}
          </n-alert>

          <n-flex :size="16" align="flex-start" class="dhcp-service-columns">
            <div style="flex: 1; min-width: 0">
              <n-form-item :label="t('dhcp_v4.service.server_ip')">
                <IpEdit
                  v-model:ip="server_ip_addr"
                  v-model:mask="network_mask"
                  :mask_max="30"
                  :ip_version="4"
                ></IpEdit>
              </n-form-item>
              <n-form-item :label="t('dhcp_v4.service.range_start')">
                <IpEdit
                  v-model:ip="service_config.config.ip_range_start"
                  :ip_version="4"
                ></IpEdit>
              </n-form-item>
              <n-form-item :label="t('dhcp_v4.service.range_end')">
                <IpEdit
                  v-model:ip="service_config.config.ip_range_end"
                  :ip_version="4"
                ></IpEdit>
              </n-form-item>
              <n-form-item :label="t('dhcp_v4.lease_time')">
                <n-input-number
                  v-model:value="service_config.config.address_lease_time"
                  :min="60"
                  :placeholder="'86400'"
                  style="width: 100%"
                />
                <template #feedback>
                  {{ t("dhcp_v4.lease_time_tip") }}
                </template>
              </n-form-item>
            </div>

            <div style="flex: 1; min-width: 0">
              <n-form-item :label="t('dhcp_v4.custom_options')">
                <div class="custom-options-scroll">
                  <CustomDhcpOptionEditor
                    ref="optionEditorRef"
                    v-model="service_config.config.custom_options"
                  />
                </div>
              </n-form-item>
            </div>
          </n-flex>
        </n-form>
      </n-flex>
    </div>

    <template #footer>
      <n-flex justify="space-between" align="center">
        <n-button round @click="show_model = false">
          {{ t("common.cancel") }}
        </n-button>
        <n-button
          :loading="commit_loading"
          round
          type="primary"
          @click="save_config"
        >
          {{ t("common.update") }}
        </n-button>
      </n-flex>
    </template>
  </ConfigModal>

  <IfaceDisableGuardModal
    ref="disable_guard_modal"
    :iface_name="iface_name"
    @refresh="emit('refresh')"
  />
</template>

<style scoped>
.custom-options-scroll {
  max-height: calc(80vh - 220px);
  min-height: 120px;
  overflow-y: auto;
  padding-right: 6px;
  width: 100%;
}

.dhcp-service-body {
  max-height: calc(80vh - 100px);
  overflow: hidden;
}

.dhcp-service-form-wrap,
.dhcp-service-form {
  width: 100%;
}

.dhcp-service-columns {
  margin-top: 16px;
  width: 100%;
}
</style>
