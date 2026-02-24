<script setup lang="ts">
import { change_zone } from "@/api/network";
import { del_route_lans } from "@/api/route/lan";
import { del_route_wans } from "@/api/route/wan";
import { stop_and_del_iface_dhcp_v4 } from "@/api/service_dhcp_v4";
import { stop_and_del_iface_firewall } from "@/api/service_firewall";
import { stop_and_del_iface_icmpv6ra } from "@/api/service_icmpv6ra";
import { stop_and_del_iface_config } from "@/api/service_ipconfig";
import { stop_and_del_iface_ipv6pd } from "@/api/service_ipv6pd";
import { stop_and_del_iface_nat } from "@/api/service_nat";
import { delete_and_stop_iface_pppd_by_attach_iface_name } from "@/api/service_pppd";
import { ZoneType } from "@/lib/service_ipconfig";
import { IfaceZoneType } from "@landscape-router/types/api/schemas";
import { ref } from "vue";

const showModal = defineModel<boolean>("show", { required: true });
const emit = defineEmits(["refresh"]);

const iface_info = defineProps<{
  iface_name: string;
  zone: IfaceZoneType;
}>();

const spin = ref(false);
const temp_zone = ref(iface_info.zone);

async function chageIfaceZone() {
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
        title="切换网卡区域"
        :bordered="false"
        role="dialog"
        aria-modal="true"
      >
        <n-flex style="flex: 1" vertical>
          <n-alert style="flex: 1" type="warning">
            切换区域会导致在该网卡上运行的服务全部重置 <br />
            且建议将当前网卡在 `/etc/network/interfaces` 中的 IP 配置方式设置为
            manual
          </n-alert>
          <n-flex justify="center">
            <n-radio-group v-model:value="temp_zone" name="iface_service_type">
              <n-radio-button :value="ZoneType.Wan" label="WAN" />
              <n-radio-button :value="ZoneType.Lan" label="LAN" />
              <n-radio-button :value="ZoneType.Undefined" label="未定义" />
            </n-radio-group>
          </n-flex>
        </n-flex>

        <template #action>
          <n-flex justify="space-between">
            <n-button @click="showModal = false">取消</n-button>
            <n-button @click="chageIfaceZone" type="primary">确定</n-button>
          </n-flex>
        </template>
      </n-card>
    </n-spin>
  </n-modal>
</template>
