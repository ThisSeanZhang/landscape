<script setup lang="ts">
import { useMessage } from "naive-ui";
import { isIP } from "is-ip";
import { computed } from "vue";
import { ref } from "vue";
import type { DnsUpstreamConfig } from "@landscape-router/types/api/schemas";
import { get_dns_upstream, push_dns_upstream } from "@/api/dns_rule/upstream";
import { DnsUpstreamModeTsEnum, UPSTREAM_OPTIONS } from "@/lib/dns";
import {
  copy_context_to_clipboard,
  read_context_from_clipboard,
} from "@/lib/common";
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

const rule = ref<DnsUpstreamConfig>();

const commit_spin = ref(false);
const isModified = computed(() => {
  return JSON.stringify(rule.value) !== origin_rule_json.value;
});

async function enter() {
  if (props.rule_id) {
    rule.value = await get_dns_upstream(props.rule_id);
  } else {
    rule.value = {
      remark: "",
      mode: { t: DnsUpstreamModeTsEnum.Plaintext },
      ips: [],
      port: 53,
      enable_ip_validation: false,
    };
  }
  origin_rule_json.value = JSON.stringify(rule.value);
}

const formRef = ref();

const ipRule = {
  trigger: ["input", "blur"],
  validator(_: unknown, value: string) {
    if (!value) return new Error(t("dns_editor.upstream_edit.err_ip_required"));
    if (!isIP(value)) return new Error(t("dns_editor.upstream_edit.err_ip_invalid"));
    return true;
  },
};

const rules = {
  ips: {
    trigger: ["blur", "change"],
    validator(_: unknown, value: string[]) {
      if (!value || value.length === 0) {
        return new Error(t("dns_editor.upstream_edit.err_ips_required"));
      }
      return true;
    },
  },

  domain: {
    trigger: ["input", "blur"],
    validator(_: unknown, value: string) {
      if (rule.value?.mode.t === DnsUpstreamModeTsEnum.Plaintext) {
        return true; // Plaintext 不校验 domain
      }
      if (!value || value.trim() === "") {
        return new Error(t("dns_editor.upstream_edit.err_domain_required"));
      }
      // 可选：简单域名正则
      const domainRegex = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
      if (!domainRegex.test(value)) {
        return new Error(t("dns_editor.upstream_edit.err_domain_invalid"));
      }
      return true;
    },
  },

  "mode.http_endpoint": {
    trigger: ["blur", "input"],
    level: "warning",
    validator(_: unknown, value: string) {
      if (!value || value.trim() === "") {
        return new Error(t("dns_editor.upstream_edit.warn_default_endpoint"));
      }
      return true;
    },
  },
};

async function saveRule() {
  if (rule.value) {
    try {
      await formRef.value?.validate();
      // 如果是 HTTPS 模式且 endpoint 为空
      if (
        rule.value.mode.t === DnsUpstreamModeTsEnum.Https &&
        (!rule.value.mode.http_endpoint ||
          rule.value.mode.http_endpoint.trim() === "")
      ) {
        message.warning(t("dns_editor.upstream_edit.warn_empty_endpoint_fill"));
        rule.value.mode.http_endpoint = null as any;
      }

      commit_spin.value = true;
      await push_dns_upstream(rule.value);
      console.log("submit success");
      show.value = false;
      emit("refresh");
    } finally {
      commit_spin.value = false;
    }
  }
}

async function export_config() {
  if (rule.value) {
    let configs = rule.value;
    await copy_context_to_clipboard(message, JSON.stringify(configs, null, 2));
  }
}

async function import_rules() {
  try {
    if (rule.value) {
      let rules = JSON.parse(await read_context_from_clipboard());
      rule.value = rules;
    }
  } catch (e) {}
}
</script>

<template>
  <n-modal
    :auto-focus="false"
    v-model:show="show"
    style="width: 600px"
    class="custom-card"
    preset="card"
    :title="t('dns_editor.upstream_edit.title')"
    @after-enter="enter"
    :bordered="false"
  >
    <template #header-extra>
      <n-flex>
        <n-button :focusable="false" @click="export_config" size="tiny" strong>
          {{ t("dns_editor.upstream_edit.copy") }}
        </n-button>
        <n-button :focusable="false" @click="import_rules" size="tiny" strong>
          {{ t("dns_editor.upstream_edit.paste") }}
        </n-button>
      </n-flex>
    </template>
    <!-- {{ rule }} -->
    <n-form
      v-if="rule"
      :rules="rules"
      style="flex: 1"
      ref="formRef"
      :model="rule"
      :cols="8"
    >
      <n-grid :cols="8">
        <n-form-item-gi :span="4" :label="t('dns_editor.upstream_edit.remark')">
          <n-input
            :placeholder="t('dns_editor.upstream_edit.remark_placeholder')"
            v-model:value="rule.remark"
          />
        </n-form-item-gi>

        <n-form-item-gi :offset="1" :span="2">
          <template #label>
            <Notice>
              {{ t("dns_editor.upstream_edit.ip_validation") }}
              <template #msg>
                {{ t("dns_editor.upstream_edit.ip_validation_desc_1") }} <br />
                {{ t("dns_editor.upstream_edit.ip_validation_desc_2") }}
              </template>
            </Notice>
          </template>

          <n-switch v-model:value="rule.enable_ip_validation">
            <template #checked> {{ t("dns_editor.upstream_edit.ip_validation_on") }} </template>
            <template #unchecked>
              {{ t("dns_editor.upstream_edit.ip_validation_off") }}
            </template>
          </n-switch>
        </n-form-item-gi>

        <n-form-item-gi :span="8" :label="t('dns_editor.upstream_edit.preset_fill')">
          <DefaultUpstream v-model:rule="rule"></DefaultUpstream>
        </n-form-item-gi>

        <n-form-item-gi
          :span="4"
          :label="t('dns_editor.upstream_edit.request_mode')"
          path="mode.domain"
        >
          <n-radio-group
            v-model:value="rule.mode.t"
            name="dns_server_upstream_mode"
          >
            <n-radio-button
              v-for="mode in UPSTREAM_OPTIONS"
              :key="mode.value"
              :value="mode.value"
              :label="mode.label"
            />
          </n-radio-group>
          <!-- <n-select
            v-else
            style="width: 25%"
            v-model:value="rule.mode.t"
            filterable
            placeholder="上游请求模式"
            :options="UPSTREAM_OPTIONS"
          /> -->
        </n-form-item-gi>

        <n-form-item-gi :span="4" :label="t('dns_editor.upstream_edit.port')">
          <n-input-number
            style="flex: 1"
            :min="1"
            :max="65535"
            :placeholder="t('dns_editor.upstream_edit.port_placeholder')"
            v-model:value="rule.port"
          />
        </n-form-item-gi>

        <n-form-item-gi
          :span="4"
          v-if="rule.mode.t !== DnsUpstreamModeTsEnum.Plaintext"
          :label="t('dns_editor.upstream_edit.domain')"
        >
          <n-input
            style="width: 230px"
            :placeholder="t('dns_editor.upstream_edit.domain_placeholder')"
            v-model:value="rule.mode.domain"
          >
          </n-input>
        </n-form-item-gi>

        <n-form-item-gi
          :span="4"
          path="mode.http_endpoint"
          v-if="rule.mode.t === DnsUpstreamModeTsEnum.Https"
          :label="t('dns_editor.upstream_edit.url')"
        >
          <n-input
            :placeholder="t('dns_editor.upstream_edit.url_placeholder')"
            v-model:value="rule.mode.http_endpoint"
          >
          </n-input>
        </n-form-item-gi>

        <n-form-item-gi
          :span="8"
          :label="t('dns_editor.upstream_edit.server_ips')"
          path="ips"
        >
          <n-dynamic-input
            v-model:value="rule.ips"
            :placeholder="t('dns_editor.upstream_edit.enter_ip')"
            #="{ index }"
          >
            <n-form-item
              :path="`ips[${index}]`"
              :rule="ipRule"
              ignore-path-change
              :show-label="false"
              :show-feedback="false"
              style="margin-bottom: 0; flex: 1"
            >
              <n-input
                v-model:value="rule.ips[index]"
                :placeholder="t('dns_editor.upstream_edit.enter_ip_v46')"
                @keydown.enter.prevent
              />
            </n-form-item>
          </n-dynamic-input>
        </n-form-item-gi>
      </n-grid>
    </n-form>
    <template #footer>
      <n-flex justify="space-between">
        <n-button @click="show = false">{{ t("dns_editor.upstream_edit.cancel") }}</n-button>
        <n-button
          :loading="commit_spin"
          @click="saveRule"
          :disabled="!isModified"
        >
          {{ t("dns_editor.upstream_edit.save") }}
        </n-button>
      </n-flex>
    </template>
  </n-modal>
</template>
