<script setup lang="ts">
import { computed, ref } from "vue";
import WanRuleEditModal from "./WanRuleEditModal.vue";
import WanRuleCard from "./WanRuleCard.vue";
import {
  get_flow_dst_ip_rules,
  push_many_dst_ip_rule,
} from "@/api/dst_ip_rule";
import {
  copy_context_to_clipboard,
  read_context_from_clipboard,
} from "@/lib/common";

import { useMessage } from "naive-ui";
import { useI18n } from "vue-i18n";
const message = useMessage();
const { t } = useI18n();

interface Props {
  flow_id?: number;
}

const props = withDefaults(defineProps<Props>(), {
  flow_id: 0,
});

const show = defineModel<boolean>("show", { required: true });

const rules = ref<any>([]);
async function read_rules() {
  rules.value = await get_flow_dst_ip_rules(props.flow_id);
}

const show_create_modal = ref(false);

async function export_config() {
  let configs = await get_flow_dst_ip_rules(props.flow_id);
  await copy_context_to_clipboard(
    message,
    JSON.stringify(
      configs,
      (key, value) => {
        if (key === "id") {
          return undefined;
        }
        // if (key === "flow_id") {
        //   return undefined;
        // }
        return value;
      },
      2,
    ),
  );
}

async function import_rules() {
  try {
    let rules = JSON.parse(await read_context_from_clipboard());
    for (const rule of rules) {
      rule.flow_id = props.flow_id;
    }
    await push_many_dst_ip_rule(rules);
    message.success("Import Success");
    await read_rules();
  } catch (e) {}
}

const title = computed(() => {
  if (props.flow_id === 0) {
    return t("flow.wan_rule_drawer.title_default");
  } else {
    return t("flow.wan_rule_drawer.title_flow", { flow_id: props.flow_id });
  }
});
</script>
<template>
  <n-drawer
    @after-enter="read_rules()"
    v-model:show="show"
    width="500px"
    placement="right"
  >
    <n-drawer-content :title="title" closable>
      <n-flex style="height: 100%" vertical>
        <n-flex>
          <n-button style="flex: 1" @click="show_create_modal = true">
            {{ t("flow.wan_rule_drawer.add_rule") }}
          </n-button>
          <n-button style="flex: 1" @click="export_config">
            {{ t("flow.wan_rule_drawer.export_clipboard") }}
          </n-button>
          <n-popconfirm @positive-click="import_rules">
            <template #trigger>
              <n-button style="flex: 1" @click="">
                {{ t("flow.wan_rule_drawer.import_clipboard") }}
              </n-button>
            </template>
            {{ t("flow.wan_rule_drawer.confirm_import") }}
          </n-popconfirm>
        </n-flex>

        <n-scrollbar>
          <n-flex vertical>
            <WanRuleCard
              @refresh="read_rules()"
              v-for="rule in rules"
              :key="rule.index"
              :rule="rule"
            >
            </WanRuleCard>
          </n-flex>
        </n-scrollbar>
      </n-flex>

      <WanRuleEditModal
        :id="null"
        :flow_id="flow_id"
        v-model:show="show_create_modal"
        @refresh="read_rules()"
      ></WanRuleEditModal>
    </n-drawer-content>
  </n-drawer>
</template>
