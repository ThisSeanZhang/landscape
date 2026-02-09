<script setup lang="ts">
import { computed, ref } from "vue";
import CreatePPPDConfigModal from "@/components/pppd/CreatePPPDConfigModal.vue";
import { PPPDServiceConfig } from "@/lib/pppd";
import { stop_and_del_iface_pppd } from "@/api/service_pppd";
import { useFrontEndStore } from "@/stores/front_end_config";
import { mask_string } from "@/lib/common";

const frontEndStore = useFrontEndStore();

const config = defineModel<PPPDServiceConfig>("config", { required: true });

const show_create_pppd_modal = ref(false);
const emit = defineEmits(["refresh"]);

async function del() {
  await stop_and_del_iface_pppd(config.value.iface_name);
  emit("refresh");
}
</script>
<template>
  <n-flex>
    <n-card :title="`网卡: ${config.iface_name}`" size="small">
      <!-- {{ rule }} -->
      <n-descriptions bordered label-placement="top" :column="3">
        <n-descriptions-item label="附着网卡">
          {{ config.attach_iface_name }}
        </n-descriptions-item>
        <n-descriptions-item label="启用">
          <n-tag :bordered="false" :type="config.enable ? 'success' : ''">
            {{ config.enable }}
          </n-tag>
        </n-descriptions-item>
        <n-descriptions-item label="默认路由">
          {{ config.pppd_config.default_route }}
        </n-descriptions-item>
        <n-descriptions-item label="用户名">
          {{ frontEndStore.MASK_INFO(config.pppd_config.peer_id) }}
        </n-descriptions-item>
      </n-descriptions>
      <template #header-extra>
        <n-flex>
          <n-button
            type="warning"
            secondary
            @click="show_create_pppd_modal = true"
          >
            编辑
          </n-button>
          <n-popconfirm @positive-click="del()">
            <template #trigger>
              <n-button type="error" secondary @click=""> 删除 </n-button>
            </template>
            确定删除吗
          </n-popconfirm>
        </n-flex>
      </template>
    </n-card>
    <CreatePPPDConfigModal
      @refresh="emit('refresh')"
      :attach_iface_name="config.attach_iface_name"
      v-model:show="show_create_pppd_modal"
      :origin_value="config"
    />
  </n-flex>
</template>
