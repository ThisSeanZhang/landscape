<script setup lang="ts">
import { computed } from "vue";
import { ref } from "vue";
import { useMessage } from "naive-ui";
import { ChangeCatalog } from "@vicons/carbon";

import ConfigModal from "@/components/common/ConfigModal.vue";
import FlowMarkEdit from "@/components/flow/FlowMarkEdit.vue";
import IpEdit from "@/components/IpEdit.vue";
import type {
  WanIPRuleSource,
  WanIpRuleConfig,
} from "@landscape-router/types/api/schemas";

import { createWanIpRule } from "@/lib/flow/mark";
import {
  get_dst_ip_rules_rule,
  push_dst_ip_rules_rule,
  update_dst_ip_rules_rule,
} from "@/api/dst_ip_rule";
import {
  copy_context_to_clipboard,
  read_context_from_clipboard,
} from "@/lib/common";
import { useI18n } from "vue-i18n";

interface Props {
  flow_id: number;
  id: string | null;
}

const props = defineProps<Props>();

const message = useMessage();
const { t } = useI18n();
const emit = defineEmits(["refresh"]);
const show = defineModel<boolean>("show", { required: true });

async function enter() {
  if (props.id !== null) {
    rule.value = await get_dst_ip_rules_rule(props.id);
  } else {
    rule.value = createWanIpRule({
      flow_id: props.flow_id,
    });
  }
  origin_rule_json.value = JSON.stringify(rule.value);
}

const origin_rule_json = ref("");
// const origin_rule = defineModel<WanIPRuleConfig>("rule", {
//   default: new WanIPRuleConfigClass({
//     flow_id: props.flow_id,
//   }),
// });
const rule = ref<WanIpRuleConfig>();

const commit_spin = ref(false);
const isModified = computed(() => {
  return origin_rule_json.value !== JSON.stringify(rule.value);
});

const rule_enabled = computed({
  get() {
    return rule.value?.enable ?? false;
  },
  set(value: boolean) {
    if (rule.value) {
      rule.value.enable = value;
    }
  },
});

function onCreate(): WanIPRuleSource {
  return { t: "config", ip: "0.0.0.0", prefix: 32 };
}

function changeCurrentRuleType(value: WanIPRuleSource, index: number) {
  if (rule.value) {
    if (value.t == "config") {
      rule.value.source[index] = {
        t: "geo_key",
        name: "",
        key: "",
        inverse: false,
        attribute_key: null,
      };
    } else {
      rule.value.source[index] = onCreate();
    }
  }
}

async function saveRule() {
  if (rule.value) {
    if (rule.value.index == -1) {
      message.warning(t("flow.wan_rule_edit.duplicate_priority_warning"));
      return;
    }
    try {
      commit_spin.value = true;
      if (props.id) {
        await update_dst_ip_rules_rule(props.id, rule.value);
      } else {
        await push_dst_ip_rules_rule(rule.value);
      }
      console.log("submit success");
      show.value = false;
    } catch (e: any) {
      message.error(`${e.response.data}`);
    } finally {
      commit_spin.value = false;
    }
    emit("refresh");
  }
}

async function export_config() {
  if (rule.value) {
    let configs = rule.value.source;
    await copy_context_to_clipboard(message, JSON.stringify(configs, null, 2));
  }
}

async function import_rules() {
  if (rule.value) {
    try {
      let rules = JSON.parse(await read_context_from_clipboard());
      rule.value.source = rules;
    } catch (e) {}
  }
}

async function append_import_rules() {
  if (rule.value) {
    try {
      let rules = JSON.parse(await read_context_from_clipboard());
      rule.value.source.unshift(...rules);
    } catch (e) {}
  }
}
</script>

<template>
  <ConfigModal
    v-model:show="show"
    v-model:enabled="rule_enabled"
    :title="t('flow.wan_rule_edit.title')"
    :switch-disabled="!rule"
    width="700px"
    @after-enter="enter"
  >
    <!-- {{ isModified }} -->
    <n-form v-if="rule" style="flex: 1" ref="formRef" :model="rule" :cols="5">
      <n-grid :cols="5" :x-gap="12">
        <n-form-item-gi :label="t('common.name')" :span="3">
          <n-input v-model:value="rule.name" />
        </n-form-item-gi>
        <n-form-item-gi :label="t('flow.wan_rule_edit.priority')" :span="2">
          <n-input-number v-model:value="rule.index" clearable />
        </n-form-item-gi>
        <!-- <n-form-item-gi label="覆盖 DNS 配置" :span="1">
          <n-switch v-model:value="rule.override_dns">
            <template #checked> 覆盖 </template>
            <template #unchecked> 不覆盖 </template>
          </n-switch>
        </n-form-item-gi> -->

        <n-form-item-gi
          :span="5"
          :label="t('flow.wan_rule_edit.egress_select')"
        >
          <FlowMarkEdit v-model:mark="rule.mark"></FlowMarkEdit>
        </n-form-item-gi>
      </n-grid>
      <n-form-item>
        <template #label>
          <n-flex
            align="center"
            justify="space-between"
            :wrap="false"
            @click.stop
          >
            <n-flex> {{ t("flow.wan_rule_edit.matched_ips") }} </n-flex>
            <n-flex>
              <!-- 不确定为什么点击 label 会触发第一个按钮, 所以放置一个不可见的按钮 -->
              <button
                style="
                  width: 0;
                  height: 0;
                  overflow: hidden;
                  opacity: 0;
                  position: absolute;
                "
              ></button>

              <n-button :focusable="false" size="tiny" @click="export_config">
                {{ t("flow.wan_rule_edit.copy") }}
              </n-button>
              <n-button :focusable="false" size="tiny" @click="import_rules">
                {{ t("flow.wan_rule_edit.paste_replace") }}
              </n-button>
              <n-button
                :focusable="false"
                size="tiny"
                @click="append_import_rules"
              >
                {{ t("flow.wan_rule_edit.paste_append") }}
              </n-button>
            </n-flex>
          </n-flex>
        </template>
        <n-dynamic-input v-model:value="rule.source" :on-create="onCreate">
          <template #create-button-default>
            {{ t("flow.wan_rule_edit.add_wan_rule") }}
          </template>
          <template #default="{ value, index }">
            <n-flex style="flex: 1" :wrap="false">
              <n-button @click="changeCurrentRuleType(value, index)">
                <n-icon>
                  <ChangeCatalog />
                </n-icon>
              </n-button>
              <GeoIpKeySelect
                v-model:geo_key="value.key"
                v-model:geo_name="value.name"
                v-if="value.t === 'geo_key'"
              >
              </GeoIpKeySelect>
              <!-- <n-input
                v-model:value="value.key"
                placeholder="geo key"
                type="text"
              /> -->
              <n-flex v-else style="flex: 1">
                <IpEdit
                  v-model:ip="value.ip"
                  v-model:mask="value.prefix"
                ></IpEdit>
              </n-flex>
            </n-flex>
          </template>
        </n-dynamic-input>
      </n-form-item>
      <n-form-item :label="t('flow.wan_rule_edit.remark')">
        <n-input v-model:value="rule.remark" type="text" />
      </n-form-item>
    </n-form>
    <template #footer>
      <n-flex justify="space-between">
        <n-button @click="show = false">{{ t("common.cancel") }}</n-button>
        <n-button
          :loading="commit_spin"
          @click="saveRule"
          :disabled="!isModified"
        >
          {{ t("common.save") }}
        </n-button>
      </n-flex>
    </template>
  </ConfigModal>
</template>
