<script setup lang="ts">
import { change_zone } from "@/api/network";
import { del_route_lans } from "@/api/route/lan";
import { del_route_wans } from "@/api/route/wan";
import { stop_and_del_iface_dhcp_v4 } from "@/api/service_dhcp_v4";
import { stop_and_del_iface_firewall } from "@/api/service_firewall";
import { stop_and_del_lan_ipv6 } from "@/api/service_lan_ipv6";
import { stop_and_del_iface_config } from "@/api/service_ipconfig";
import { stop_and_del_iface_ipv6pd } from "@/api/service_ipv6pd";
import { stop_and_del_iface_nat } from "@/api/service_nat";
import { delete_and_stop_iface_pppd_by_attach_iface_name } from "@/api/service_pppd";
import { IfaceZoneType } from "@landscape-router/types/api/schemas";
import IfaceDisableGuardModal from "@/components/iface/IfaceDisableGuardModal.vue";
import { ref } from "vue";
import { useI18n } from "vue-i18n";

const { t } = useI18n();

const showModal = defineModel<boolean>("show", { required: true });
const emit = defineEmits(["refresh"]);

const iface_info = defineProps<{
  iface_name: string;
  zone: IfaceZoneType;
}>();

const spin = ref(false);
const temp_zone = ref(iface_info.zone);
const disable_guard_modal = ref<InstanceType<
  typeof IfaceDisableGuardModal
> | null>(null);

async function chageIfaceZone() {
  const action = async () => {
    spin.value = true;
    try {
      await change_zone({
        iface_name: iface_info.iface_name,
        zone: temp_zone.value,
      });
      // TODO 调用 拓扑刷新
      emit("refresh");
      showModal.value = false;
    } catch (error) {
    } finally {
      spin.value = false;
    }
  };

  if (disable_guard_modal.value) {
    await disable_guard_modal.value.check_and_execute(action);
  } else {
    await action();
  }
}

function reflush_zone() {
  temp_zone.value = iface_info.zone;
}
</script>

<template>
  <n-modal
    @after-enter="reflush_zone"
    :auto-focus="false"
    v-model:show="showModal"
  >
    <n-spin :show="spin">
      <n-card
        style="width: 600px; display: flex"
        :title="t('interface.change_zone_title')"
        :bordered="false"
        role="dialog"
        aria-modal="true"
      >
        <n-flex style="flex: 1" vertical>
          <n-alert style="flex: 1" type="warning">
            {{ t("interface.change_zone_warning_1") }} <br />
            {{ t("interface.change_zone_warning_2") }}
          </n-alert>
          <n-flex justify="center">
            <n-radio-group v-model:value="temp_zone" name="iface_service_type">
              <n-radio-button :value="IfaceZoneType.wan" label="WAN" />
              <n-radio-button :value="IfaceZoneType.lan" label="LAN" />
              <n-radio-button
                :value="IfaceZoneType.undefined"
                :label="t('interface.zone_undefined')"
              />
            </n-radio-group>
          </n-flex>
        </n-flex>

        <template #action>
          <n-flex justify="space-between">
            <n-button @click="showModal = false">{{
              t("common.cancel")
            }}</n-button>
            <n-button @click="chageIfaceZone" type="primary">{{
              t("common.confirm")
            }}</n-button>
          </n-flex>
        </template>
      </n-card>
    </n-spin>
  </n-modal>

  <IfaceDisableGuardModal
    ref="disable_guard_modal"
    :iface_name="iface_name"
    @refresh="emit('refresh')"
  />
</template>
