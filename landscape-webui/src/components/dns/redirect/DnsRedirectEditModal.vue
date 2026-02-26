<script setup lang="ts">
import { useMessage } from "naive-ui";

import { isIP } from "is-ip";
import { computed, onMounted } from "vue";
import { ref } from "vue";
import {
  copy_context_to_clipboard,
  read_context_from_clipboard,
} from "@/lib/common";
import type { DNSRedirectRule } from "@landscape-router/types/api/schemas";
import { get_dns_redirect, push_dns_redirect } from "@/api/dns_rule/redirect";
import { getFlowRules } from "@landscape-router/types/api/flow-rules/flow-rules";
import { useI18n } from "vue-i18n";

type Props = {
  rule_id: string | null;
};

const props = defineProps<Props>();

const message = useMessage();
const { t } = useI18n();

const emit = defineEmits(["refresh"]);

const show = defineModel<boolean>("show", { required: true });

const origin_rule_json = ref<string>("");

const rule = ref<DNSRedirectRule>();

const commit_spin = ref(false);
const isModified = computed(() => {
  return JSON.stringify(rule.value) !== origin_rule_json.value;
});

onMounted(async () => {
  await search_flows();
});

async function enter() {
  if (props.rule_id != null) {
    rule.value = await get_dns_redirect(props.rule_id);
  } else {
    rule.value = {
      enable: true,
      remark: "",
      match_rules: [],
      result_info: [],
      apply_flows: [],
    };
  }
  origin_rule_json.value = JSON.stringify(rule.value);
}

const formRef = ref();

const ipRule = {
  trigger: ["input", "blur"],
  validator(_: unknown, value: string) {
    if (!value) return new Error(t("dns_editor.redirect_edit.err_ip_required"));
    if (!isIP(value)) return new Error(t("dns_editor.redirect_edit.err_ip_invalid"));
    return true;
  },
};

const rules = {
  match_rules: {
    trigger: ["blur", "change"],
    validator(_: unknown, value: any[]) {
      if (!value || value.length === 0) {
        return new Error(t("dns_editor.redirect_edit.err_match_rules_required"));
      }
      return true;
    },
  },
};

async function saveRule() {
  if (rule.value) {
    try {
      await formRef.value?.validate();
      commit_spin.value = true;
      await push_dns_redirect(rule.value);
      console.log("submit success");
      show.value = false;
      emit("refresh");
    } finally {
      commit_spin.value = false;
    }
  }
}

const flow_rules = ref<any[]>([]);
const flow_options = computed(() => {
  const result = flow_rules.value.map((e) => ({
    value: e.flow_id,
    label: e.remark ? `${e.flow_id} - ${e.remark}` : e.flow_id,
  }));
  result.unshift({
    label: t("dns_editor.redirect_edit.default_flow"),
    value: 0,
  });
  return result;
});
const flow_search_loading = ref(false);
async function search_flows() {
  flow_rules.value = await getFlowRules();
}

async function export_config() {
  if (rule.value) {
    let configs = rule.value.match_rules;
    await copy_context_to_clipboard(message, JSON.stringify(configs, null, 2));
  }
}

async function import_rules() {
  try {
    if (rule.value) {
      let rules = JSON.parse(await read_context_from_clipboard());
      rule.value.match_rules = rules;
    }
  } catch (e) {}
}

async function append_import_rules() {
  try {
    if (rule.value) {
      let rules = JSON.parse(await read_context_from_clipboard());
      rule.value.match_rules.unshift(...rules);
    }
  } catch (e) {}
}
</script>

<template>
  <n-modal
    v-model:show="show"
    style="width: 600px"
    class="custom-card"
    preset="card"
    :title="t('dns_editor.redirect_edit.title')"
    @after-enter="enter"
    :bordered="false"
  >
    <!-- {{ isModified }} -->
    <n-form
      v-if="rule"
      :rules="rules"
      style="flex: 1"
      ref="formRef"
      :model="rule"
      :cols="5"
    >
      <n-grid :cols="2">
        <!-- <n-form-item-gi label="优先级" :span="2">
          <n-input-number v-model:value="rule.index" clearable />
        </n-form-item-gi> -->
        <n-form-item-gi :label="t('dns_editor.redirect_edit.enable')" :span="1">
          <n-switch v-model:value="rule.enable">
            <template #checked> {{ t("dns_editor.redirect_edit.enabled_yes") }} </template>
            <template #unchecked> {{ t("dns_editor.redirect_edit.enabled_no") }} </template>
          </n-switch>
        </n-form-item-gi>

        <n-form-item-gi :span="2" :label="t('dns_editor.redirect_edit.remark')">
          <n-input v-model:value="rule.remark" />
        </n-form-item-gi>

        <n-form-item-gi :span="2" :label="t('dns_editor.redirect_edit.apply_flows')">
          <n-select
            multiple
            v-model:value="rule.apply_flows"
            filterable
            :placeholder="t('dns_editor.redirect_edit.apply_flows_placeholder')"
            :options="flow_options"
            :loading="flow_search_loading"
            clearable
            remote
            @search="search_flows"
          />
        </n-form-item-gi>

        <n-form-item-gi
          :span="2"
          :label="t('dns_editor.redirect_edit.redirect_result')"
          path="result_info"
        >
          <n-dynamic-input
            v-model:value="rule.result_info"
            :placeholder="t('dns_editor.redirect_edit.enter_ip')"
            #="{ index }"
          >
            <n-form-item
              :path="`result_info[${index}]`"
              :rule="ipRule"
              ignore-path-change
              :show-label="false"
              :show-feedback="false"
              style="margin-bottom: 0; flex: 1"
            >
              <n-input
                v-model:value="rule.result_info[index]"
                :placeholder="t('dns_editor.redirect_edit.enter_ip_v46')"
                @keydown.enter.prevent
              />
            </n-form-item>
          </n-dynamic-input>
        </n-form-item-gi>

        <n-form-item-gi
          :span="2"
          :label="t('dns_editor.redirect_edit.match_rules')"
          path="match_rules"
        >
          <template #label>
            <n-flex
              align="center"
              justify="space-between"
              :wrap="false"
              @click.stop
            >
              <n-flex> {{ t("dns_editor.redirect_edit.match_rules_header") }} </n-flex>
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
                  {{ t("dns_editor.redirect_edit.copy") }}
                </n-button>
                <n-button :focusable="false" size="tiny" @click="import_rules">
                  {{ t("dns_editor.redirect_edit.paste_replace") }}
                </n-button>
                <n-button
                  :focusable="false"
                  size="tiny"
                  @click="append_import_rules"
                >
                  {{ t("dns_editor.redirect_edit.paste_append") }}
                </n-button>
              </n-flex>
            </n-flex>
          </template>

          <DomainMatchInput v-model:source="rule.match_rules">
          </DomainMatchInput>
        </n-form-item-gi>
      </n-grid>
    </n-form>
    <template #footer>
      <n-flex justify="space-between">
        <n-button @click="show = false">{{ t("dns_editor.redirect_edit.cancel") }}</n-button>
        <n-button
          :loading="commit_spin"
          @click="saveRule"
          :disabled="!isModified"
        >
          {{ t("dns_editor.redirect_edit.save") }}
        </n-button>
      </n-flex>
    </template>
  </n-modal>
</template>
