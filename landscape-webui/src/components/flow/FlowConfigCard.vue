<script setup lang="ts">
import { computed, ref } from "vue";
import { FlowConfig } from "@/rust_bindings/common/flow";
import FlowEditModal from "@/components/flow/FlowEditModal.vue";
import DnsRuleDrawer from "@/components/dns/DnsRuleDrawer.vue";
import { useFrontEndStore } from "@/stores/front_end_config";
import { mask_string } from "@/lib/common";
import { del_flow_rules } from "@/api/flow";

import { Docker, NetworkWired } from "@vicons/fa";

const frontEndStore = useFrontEndStore();

interface Props {
  config: FlowConfig;
  show_action?: boolean;
}

const props = withDefaults(defineProps<Props>(), {
  show_action: true,
});

const emit = defineEmits(["refresh"]);

const show_edit = ref(false);
const show_dns_rule = ref(false);
const show_ip_rule = ref(false);

async function refresh() {
  emit("refresh");
}

async function del() {
  if (props.config.id) {
    await del_flow_rules(props.config.id);
    await refresh();
  }
}
const title_name = computed(() =>
  props.config.remark == null || props.config.remark === ""
    ? `无备注`
    : frontEndStore.presentation_mode
    ? mask_string(props.config.remark)
    : props.config.remark
);
</script>

<template>
  <n-card
    style="min-height: 224px"
    content-style="display: flex"
    size="small"
    :hoverable="true"
  >
    <template #header>
      <StatusTitle
        :enable="config.enable"
        :remark="`${config.flow_id}: ${title_name}`"
      ></StatusTitle>
    </template>

    <template v-if="show_action" #header-extra>
      <n-flex>
        <n-button secondary @click="show_edit = true" size="small">
          修改配置
        </n-button>
        <n-button secondary @click="show_dns_rule = true" size="small">
          DNS
        </n-button>
        <n-button secondary @click="show_ip_rule = true" size="small">
          目标 IP
        </n-button>
        <n-popconfirm @positive-click="del">
          <template #trigger>
            <n-button type="error" secondary size="small">删除</n-button>
          </template>
          确定删除吗?
        </n-popconfirm>
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

    <!-- <n-descriptions bordered :column="1" label-placement="left">
      <n-descriptions-item label="入口规则">
        <n-tag v-if="config.flow_match_rules.length > 0" :bordered="false">
          {{
            `${
              config.flow_match_rules[0].vlan_id
                ? `${config.flow_match_rules[0].vlan_id}@`
                : ""
            }${config.flow_match_rules[0].ip}`
          }}
        </n-tag>
        <n-empty :show-icon="false" v-else description="没有入口规则">
        </n-empty>
      </n-descriptions-item>
      <n-descriptions-item label="分流出口">

        <n-tag v-for="each in config.flow_targets" :bordered="false">
          {{ each.t === "netns" ? each.container_name : each.name }}
          <template #icon>
            <n-icon :component="each.t === 'netns' ? Docker : NetworkWired" />
          </template>
        </n-tag>
      </n-descriptions-item>
    </n-descriptions> -->

    <n-flex
      align="center"
      justify="center"
      v-if="config.flow_match_rules.length == 0"
      style="flex: 1"
    >
      <n-empty :show-icon="false" description="没有入口规则"> </n-empty>
    </n-flex>
    <n-flex v-else>
      <n-tag v-for="item in config.flow_match_rules" :bordered="false">
        {{ `${item.vlan_id ? `${item.vlan_id}@` : ""}${item.ip}` }}
      </n-tag>
    </n-flex>
    <template #action>
      <n-tag v-for="each in config.flow_targets" :bordered="false">
        {{ each.t === "netns" ? each.container_name : each.name }}
        <template #icon>
          <n-icon :component="each.t === 'netns' ? Docker : NetworkWired" />
        </template>
      </n-tag>
    </template>

    <!-- {{ config }} -->
    <FlowEditModal
      @refresh="refresh"
      v-model:show="show_edit"
      :rule_id="props.config.id"
    >
    </FlowEditModal>
    <DnsRuleDrawer v-model:show="show_dns_rule" :flow_id="props.config.flow_id">
    </DnsRuleDrawer>
    <WanIpRuleDrawer
      :flow_id="props.config.flow_id"
      v-model:show="show_ip_rule"
    />
  </n-card>
</template>
