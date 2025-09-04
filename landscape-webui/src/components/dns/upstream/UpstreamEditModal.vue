<script setup lang="ts">
import { useMessage } from "naive-ui";
import { isIP } from "is-ip";
import { computed } from "vue";
import { ref } from "vue";
import { DnsUpstreamConfig } from "@/rust_bindings/common/dns";
import { get_dns_upstream, push_dns_upstream } from "@/api/dns_rule/upstream";
import { DnsUpstreamModeTsEnum, UPSTREAM_OPTIONS } from "@/lib/dns";
import {
  copy_context_to_clipboard,
  read_context_from_clipboard,
} from "@/lib/common";

type Props = {
  rule_id: string | null;
};

const props = defineProps<Props>();

const message = useMessage();

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
    };
  }
  origin_rule_json.value = JSON.stringify(rule.value);
}

const formRef = ref();

const ipRule = {
  trigger: ["input", "blur"],
  validator(_: unknown, value: string) {
    if (!value) return new Error("IP 地址不能为空");
    if (!isIP(value)) return new Error("请输入有效的 IPv4 或 IPv6 地址");
    return true;
  },
};

const rules = {
  ips: {
    trigger: ["blur", "change"],
    validator(_: unknown, value: string[]) {
      if (!value || value.length === 0) {
        return new Error("至少需要添加一个返回的 IP 地址");
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
        return new Error("上游域名不能为空");
      }
      // 可选：简单域名正则
      const domainRegex = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
      if (!domainRegex.test(value)) {
        return new Error("请输入有效的域名");
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
    title="DNS 上游配置"
    @after-enter="enter"
    :bordered="false"
  >
    <template #header-extra>
      <n-flex>
        <n-button :focusable="false" @click="export_config" size="tiny" strong>
          复制
        </n-button>
        <n-button :focusable="false" @click="import_rules" size="tiny" strong>
          粘贴
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
      :cols="5"
    >
      <n-grid :cols="2">
        <n-form-item-gi :span="2" label="备注">
          <n-input
            placeholder="DNS 规则中进行选择时与其他区分"
            v-model:value="rule.remark"
          />
        </n-form-item-gi>

        <n-form-item-gi :span="5" label="点击按钮可以使用预设填充">
          <DefaultUpstream v-model:rule="rule"></DefaultUpstream>
        </n-form-item-gi>

        <n-form-item-gi :span="1" label="上游请求模式" path="mode.domain">
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

        <n-form-item-gi
          v-if="rule.mode.t !== DnsUpstreamModeTsEnum.Plaintext"
          :span="1"
          label="域名"
        >
          <n-input
            placeholder="无需包含 https 以及尾部 /dns-query"
            v-model:value="rule.mode.domain"
          >
          </n-input>
        </n-form-item-gi>

        <n-form-item-gi :span="2" label="端口">
          <n-input-number
            :min="1"
            :max="65535"
            placeholder="DNS 规则中进行选择时用到"
            v-model:value="rule.port"
          />
        </n-form-item-gi>

        <n-form-item-gi :span="2" label="DNS 服务器 IP" path="ips">
          <n-dynamic-input
            v-model:value="rule.ips"
            placeholder="请输入 IP"
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
                placeholder="请输入 IPv4 或 IPv6 地址"
                @keydown.enter.prevent
              />
            </n-form-item>
          </n-dynamic-input>
        </n-form-item-gi>
      </n-grid>
    </n-form>
    <template #footer>
      <n-flex justify="space-between">
        <n-button @click="show = false">取消</n-button>
        <n-button
          :loading="commit_spin"
          @click="saveRule"
          :disabled="!isModified"
        >
          保存
        </n-button>
      </n-flex>
    </template>
  </n-modal>
</template>
