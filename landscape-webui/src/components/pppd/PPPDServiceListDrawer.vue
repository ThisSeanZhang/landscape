<script setup lang="ts">
import CreatePPPDConfigModal from "@/components/pppd/CreatePPPDConfigModal.vue";
import PPPDCard from "@/components/pppd/PPPDCard.vue";
import { get_attach_iface_pppd_config } from "@/api/service_pppd";
import { PPPDServiceConfig } from "@/lib/pppd";
import { computed, ref } from "vue";

const show = defineModel<boolean>("show", { required: true });
const props = defineProps<{
  attach_iface_name: string;
}>();

const pppd_configs = ref<PPPDServiceConfig[]>([]);
async function inti_drawer() {
  pppd_configs.value = await get_attach_iface_pppd_config(
    props.attach_iface_name
  );
}

const show_create_pppd_modal = ref(false);
</script>
<template>
  <n-drawer v-model:show="show" width="500px" @after-enter="inti_drawer">
    <n-drawer-content
      :title="`配置 ${props.attach_iface_name} PPPD 服务`"
      closable
    >
      <n-flex style="height: 100%" vertical>
        <n-button @click="show_create_pppd_modal = true">
          添加 PPPD 配置
        </n-button>

        <n-scrollbar>
          <n-flex vertical>
            <PPPDCard
              @refresh="inti_drawer"
              :config="each"
              v-for="each in pppd_configs"
            >
            </PPPDCard>
          </n-flex>
        </n-scrollbar>
      </n-flex>

      <!-- {{ pppd_configs }} -->

      <CreatePPPDConfigModal
        @refresh="inti_drawer"
        :attach_iface_name="props.attach_iface_name"
        v-model:show="show_create_pppd_modal"
        :origin_value="undefined"
      />
    </n-drawer-content>
  </n-drawer>
</template>
