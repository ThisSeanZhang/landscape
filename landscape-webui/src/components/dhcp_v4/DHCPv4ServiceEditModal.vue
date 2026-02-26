<script setup lang="ts">
import { computed, h, ref } from "vue";
import { NButton, useMessage, useNotification } from "naive-ui";
import NewIpEdit from "../NewIpEdit.vue";
import { ZoneType } from "@/lib/service_ipconfig";
import { DHCPv4ServiceConfig, get_dhcp_range } from "@/lib/dhcp_v4";
import { formatMacAddress } from "@/lib/util";
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
const iface_info = defineProps<{
  iface_name: string;
  zone: IfaceZoneType;
}>();

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
  } catch (e) {
    service_config.value = new DHCPv4ServiceConfig({
      iface_name: iface_info.iface_name,
    });
  }
}

async function save_config() {
  commit_loading.value = true;
  try {
    await update_dhcp_v4_config(service_config.value);
    await dhcpv4ConfigStore.UPDATE_INFO();
    show_model.value = false;

    // Check enrolled device binding validity after successful save.
    const invalidBindings = await check_iface_enrolled_devices_validity(
      iface_info.iface_name,
    );
    if (invalidBindings.length > 0) {
      notification.warning({
        title: t("enrolled_device.invalid_bindings_title"),
        content: t("enrolled_device.invalid_bindings_warning", {
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
              default: () => t("enrolled_device.go_to_manage"),
            },
          ),
      });
    } else {
      message.success(t("dhcp_editor.service.save_success"));
    }
  } catch (e: any) {
    console.log(e);
    message.error(e.response?.data?.msg || t("dhcp_editor.service.save_failed"));
  } finally {
    commit_loading.value = false;
  }
}

const server_ip_addr = computed({
  get() {
    return service_config.value.config.server_ip_addr;
  },
  set(new_value) {
    service_config.value.config.server_ip_addr = new_value;
    const [start, end] = get_dhcp_range(
      `${service_config.value.config.server_ip_addr}/${service_config.value.config.network_mask}`,
    );
    service_config.value.config.ip_range_start = start;
    service_config.value.config.ip_range_end = end;
  },
});

const network_mask = computed({
  get() {
    return service_config.value.config.network_mask;
  },
  set(new_value) {
    service_config.value.config.network_mask = new_value;
    const [start, end] = get_dhcp_range(
      `${service_config.value.config.server_ip_addr}/${service_config.value.config.network_mask}`,
    );
    service_config.value.config.ip_range_start = start;
    service_config.value.config.ip_range_end = end;
  },
});
</script>

<template>
  <n-modal
    :auto-focus="false"
    v-model:show="show_model"
    @after-enter="on_modal_enter"
  >
    <n-card
      style="width: 600px"
      :title="t('dhcp_editor.service.title')"
      :bordered="false"
      size="small"
      role="dialog"
      aria-modal="true"
    >
      <n-flex style="flex: 1">
        <n-alert style="flex: 1" type="warning">
          {{ t("dhcp_editor.service.warning") }}
        </n-alert>
        <n-form :model="service_config">
          <n-form-item :label="t('dhcp_editor.service.enable')">
            <n-switch v-model:value="service_config.enable">
              <template #checked> {{ t("dhcp_editor.service.enabled_yes") }} </template>
              <template #unchecked> {{ t("dhcp_editor.service.enabled_no") }} </template>
            </n-switch>
          </n-form-item>

          <n-grid :cols="5">
            <n-form-item-gi :label="t('dhcp_editor.service.server_ip')" :span="5">
              <NewIpEdit
                v-model:ip="server_ip_addr"
                v-model:mask="network_mask"
                :mask_max="30"
              ></NewIpEdit>
            </n-form-item-gi>
            <n-form-item-gi :label="t('dhcp_editor.service.range_start')" :span="5">
              <NewIpEdit
                v-model:ip="service_config.config.ip_range_start"
              ></NewIpEdit>
            </n-form-item-gi>
            <n-form-item-gi :label="t('dhcp_editor.service.range_end')" :span="5">
              <NewIpEdit
                v-model:ip="service_config.config.ip_range_end"
              ></NewIpEdit>
            </n-form-item-gi>
          </n-grid>
        </n-form>
      </n-flex>

      <template #footer>
        <n-flex justify="space-between" align="center">
          <n-button round @click="show_model = false">
            {{ t("dhcp_editor.service.cancel") }}
          </n-button>
          <n-button
            :loading="commit_loading"
            round
            type="primary"
            @click="save_config"
          >
            {{ t("dhcp_editor.service.update") }}
          </n-button>
        </n-flex>
      </template>
    </n-card>
  </n-modal>
</template>
