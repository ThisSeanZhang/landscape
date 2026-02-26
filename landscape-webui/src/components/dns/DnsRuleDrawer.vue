<script setup lang="ts">
import { computed, ref } from "vue";
import DnsRuleCard from "@/components/dns/DnsRuleCard.vue";
import {
  getFlowDnsRules,
  addManyDnsRules,
} from "@landscape-router/types/api/dns-rules/dns-rules";
import {
  copy_context_to_clipboard,
  read_context_from_clipboard,
} from "@/lib/common";
import { useMessage } from "naive-ui";
import { SearchLocate } from "@vicons/carbon";
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
  rule_loading_spin.value = true;
  try {
    rules.value = await getFlowDnsRules(props.flow_id);
  } finally {
    rule_loading_spin.value = false;
  }
}

const show_create_modal = ref(false);
const show_query_modal = ref(false);

async function export_config() {
  let configs = await getFlowDnsRules(props.flow_id);
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
    await addManyDnsRules(rules);
    message.success("Import Success");
    await read_rules();
  } catch (e) {}
}

const title = computed(() => {
  if (props.flow_id === 0) {
    return t("dns_editor.rule_drawer.title_default");
  } else {
    return t("dns_editor.rule_drawer.title_flow", { flow_id: props.flow_id });
  }
});
const rule_loading_spin = ref(false);
</script>
<template>
  <n-drawer
    @after-enter="read_rules()"
    v-model:show="show"
    width="500px"
    placement="right"
  >
    <n-drawer-content
      :loading="true"
      :title="title"
      closable
      :native-scrollbar="false"
      body-content-style="height: 100%; padding: 14px 16px"
    >
      <n-spin
        style="height: 100%"
        content-style="height: 100%"
        :show="rule_loading_spin"
      >
        <n-flex style="height: 100%" vertical>
          <n-flex>
            <n-button style="flex: 1" @click="show_create_modal = true">
              {{ t("dns_editor.rule_drawer.add_rule") }}
            </n-button>
            <n-button style="flex: 1" @click="export_config">
              {{ t("dns_editor.rule_drawer.export_clipboard") }}
            </n-button>
            <n-popconfirm @positive-click="import_rules">
              <template #trigger>
                <n-button style="flex: 1" @click="">
                  {{ t("dns_editor.rule_drawer.import_clipboard") }}
                </n-button>
              </template>
              {{ t("dns_editor.rule_drawer.confirm_import") }}
            </n-popconfirm>
            <n-button @click="show_query_modal = true">
              <template #icon>
                <n-icon>
                  <SearchLocate />
                </n-icon>
              </template>
            </n-button>
          </n-flex>
          <n-scrollbar>
            <n-flex vertical>
              <DnsRuleCard
                @refresh="read_rules()"
                v-for="rule in rules"
                :key="rule.index"
                :rule="rule"
              >
              </DnsRuleCard>
            </n-flex>
          </n-scrollbar>
        </n-flex>
      </n-spin>
      <DnsRuleEditModal
        v-model:show="show_create_modal"
        :flow_id="props.flow_id"
        :rule_id="null"
        @refresh="read_rules()"
      ></DnsRuleEditModal>
      <CheckDomainDrawer
        v-model:show="show_query_modal"
        :flow_id="flow_id"
      ></CheckDomainDrawer>
    </n-drawer-content>
  </n-drawer>
</template>
