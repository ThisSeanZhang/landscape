<script setup lang="ts">
import { ref } from "vue";
import { FlowConfig } from "@/rust_bindings/flow";
import { FlowTargetTypes } from "@/lib/default_value";
import FlowEditModal from "@/components/flow/FlowEditModal.vue";
import DnsRuleDrawer from "@/components/dns/DnsRuleDrawer.vue";

interface Props {
  config: FlowConfig;
}

const props = defineProps<Props>();

const show_edit = ref(false);
const show_dns_rule = ref(false);
const show_ip_rule = ref(false);
</script>

<template>
  <n-card size="small" :title="`ID: ${config.flow_id}`" :hoverable="true">
    <template #header-extra>
      <n-flex>
        <n-button @click="show_edit = true" size="small">修改配置</n-button>
        <n-button @click="show_dns_rule = true" size="small"> DNS </n-button>
        <n-button @click="show_ip_rule = true" size="small">目标 IP</n-button>
      </n-flex>
    </template>

    <template #footer>
      <!-- <n-flex>
        <n-tag :bordered="false" v-for="rule in config.flow_match_rules">
          {{ `${rule.ip} - ${rule.qos ?? "N/A"} - ${rule.vlan_id ?? "N/A"}` }}
        </n-tag>
      </n-flex>
    </template>
    <template #action>
      <n-flex>
        <n-tag
          :bordered="false"
          v-for="target in config.packet_handle_iface_name"
          :type="`${target.t === FlowTargetTypes.NETNS ? 'info' : ''}`"
        >
          {{
            target.t === FlowTargetTypes.NETNS
              ? target.container_name
              : target.name
          }}
        </n-tag>
      </n-flex> -->
    </template>

    <n-descriptions :column="1" label-placement="left">
      <n-descriptions-item label="状态">
        {{ config.enable ? "启用" : "禁用" }}
      </n-descriptions-item>
      <n-descriptions-item label="备注">
        {{ config.remark }}
      </n-descriptions-item>
    </n-descriptions>
    <!-- {{ config }} -->
    <FlowEditModal v-model:show="show_edit" :rule="props.config">
    </FlowEditModal>
    <DnsRuleDrawer v-model:show="show_dns_rule" :flow_id="props.config.flow_id">
    </DnsRuleDrawer>
    <WanIpRuleDrawer
      :flow_id="props.config.flow_id"
      v-model:show="show_ip_rule"
    />
  </n-card>
</template>
