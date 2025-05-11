<script setup lang="ts">
import { change_zone } from "@/api/network";
import { stop_and_del_iface_firewall } from "@/api/service_firewall";
import { stop_and_del_iface_config } from "@/api/service_ipconfig";
import { stop_and_del_iface_ipv6pd } from "@/api/service_ipv6pd";
import { stop_and_del_iface_mark } from "@/api/service_mark";
import { stop_and_del_iface_nat } from "@/api/service_nat";
import { delete_and_stop_iface_pppd_by_attach_iface_name } from "@/api/service_pppd";
import { ZoneType } from "@/lib/service_ipconfig";
import { IfaceZoneType } from "@/rust_bindings/common/iface";
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
    await stop_and_del_iface_config(iface_info.iface_name);
    await stop_and_del_iface_nat(iface_info.iface_name);
    await delete_and_stop_iface_pppd_by_attach_iface_name(
      iface_info.iface_name
    );
    await stop_and_del_iface_ipv6pd(iface_info.iface_name);
    await stop_and_del_iface_firewall(iface_info.iface_name);
    await stop_and_del_iface_mark(iface_info.iface_name);
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
        style="width: 400px; display: flex"
        title="切换网卡区域"
        :bordered="false"
        role="dialog"
        aria-modal="true"
      >
        <n-flex justify="center">
          <n-alert type="warning">
            切换区域会导致在该网卡上运行的服务全部重置
          </n-alert>
          <n-radio-group v-model:value="temp_zone" name="iface_service_type">
            <n-radio-button :value="ZoneType.Wan" label="WAN" />
            <n-radio-button :value="ZoneType.Lan" label="LAN" />
            <n-radio-button :value="ZoneType.Undefined" label="未定义" />
          </n-radio-group>
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
