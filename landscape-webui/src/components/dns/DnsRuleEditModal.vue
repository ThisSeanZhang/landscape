<script setup lang="ts">
import { get_dns_rule, push_dns_rule } from "@/api/dns_rule";
import {
  DnsRule,
  get_dns_resolve_mode_options,
  get_dns_upstream_type_options,
  get_dns_filter_options,
  DNSResolveModeEnum,
  DnsUpstreamTypeEnum,
  CloudflareMode,
  DomainMatchTypeEnum,
  RuleSourceEnum,
} from "@/lib/dns";
import { useMessage } from "naive-ui";

import { ChangeCatalog } from "@vicons/carbon";
import { computed, onMounted } from "vue";
import { ref } from "vue";
import FlowMarkEdit from "@/components/flow/FlowMarkEdit.vue";
import { RuleSource } from "@/rust_bindings/common/dns";
import {
  copy_context_to_clipboard,
  read_context_from_clipboard,
} from "@/lib/common";

type Props = {
  flow_id: number;
  rule_id?: string;
};

const props = defineProps<Props>();

const message = useMessage();

const emit = defineEmits(["refresh"]);

const show = defineModel<boolean>("show", { required: true });

const origin_rule_json = ref<string>("");

const rule = ref<any>(new DnsRule());

const commit_spin = ref(false);
const isModified = computed(() => {
  return JSON.stringify(rule.value) !== origin_rule_json.value;
});

async function enter() {
  if (props.rule_id != null) {
    rule.value = await get_dns_rule(props.rule_id);
  } else {
    rule.value = new DnsRule({
      flow_id: props.flow_id,
    });
  }
  origin_rule_json.value = JSON.stringify(rule.value);
}

function onCreate(): RuleSource {
  return {
    t: RuleSourceEnum.GeoKey,
    key: "",
    name: "",
    inverse: false,
    attribute_key: null,
  };
}

function changeCurrentRuleType(value: RuleSource, index: number) {
  if (value.t == RuleSourceEnum.GeoKey) {
    rule.value.source[index] = {
      t: "config",
      match_type: DomainMatchTypeEnum.Full,
      value: value.key,
    };
  } else {
    rule.value.source[index] = { t: RuleSourceEnum.GeoKey, key: value.value };
  }
}

async function saveRule() {
  if (rule.value.index == -1) {
    message.warning("**优先级** 值不能为 -1, 且不能重复, 否则将会覆盖规则");
    return;
  }
  try {
    commit_spin.value = true;
    await push_dns_rule(rule.value);
    console.log("submit success");
    show.value = false;
  } catch (e: any) {
    message.error(`${e.response.data}`);
  } finally {
    commit_spin.value = false;
  }
  emit("refresh");
}

const source_style = [
  {
    label: "精确匹配",
    value: DomainMatchTypeEnum.Full,
  },
  {
    label: "域名匹配",
    value: DomainMatchTypeEnum.Domain,
  },
  {
    label: "正则匹配",
    value: DomainMatchTypeEnum.Regex,
  },
  {
    label: "关键词匹配",
    value: DomainMatchTypeEnum.Plain,
  },
];

async function export_config() {
  let configs = rule.value.source;
  await copy_context_to_clipboard(message, JSON.stringify(configs, null, 2));
}

async function import_rules() {
  try {
    let rules = JSON.parse(await read_context_from_clipboard());
    rule.value.source = rules;
  } catch (e) {}
}
</script>

<template>
  <n-modal
    v-model:show="show"
    style="width: 600px"
    class="custom-card"
    preset="card"
    title="规则编辑"
    @after-enter="enter"
    :bordered="false"
  >
    <!-- {{ isModified }} -->
    <n-form style="flex: 1" ref="formRef" :model="rule" :cols="5">
      <n-grid :cols="5">
        <n-form-item-gi label="优先级" :span="2">
          <n-input-number v-model:value="rule.index" clearable />
        </n-form-item-gi>
        <n-form-item-gi label="启用" :offset="1" :span="1">
          <n-switch v-model:value="rule.enable">
            <template #checked> 启用 </template>
            <template #unchecked> 禁用 </template>
          </n-switch>
        </n-form-item-gi>

        <n-form-item-gi :span="5" label="是否过滤结果">
          <!-- {{ rule }} -->
          <n-radio-group v-model:value="rule.filter" name="filter">
            <n-radio-button
              v-for="opt in get_dns_filter_options()"
              :key="opt.value"
              :value="opt.value"
              :label="opt.label"
            />
          </n-radio-group>
        </n-form-item-gi>

        <n-form-item-gi :span="2" label="备注">
          <n-input v-model:value="rule.name" type="text" />
        </n-form-item-gi>
        <n-form-item-gi :span="5" label="流量动作">
          <!-- <n-popover trigger="hover">
            <template #trigger>
              <n-switch v-model:value="rule.mark">
                <template #checked> 标记 </template>
                <template #unchecked> 不标记 </template>
              </n-switch>
            </template>
            <span>向上游 DNS 请求时的流量是否标记</span>
          </n-popover> -->
          <FlowMarkEdit v-model:mark="rule.mark"></FlowMarkEdit>
        </n-form-item-gi>

        <n-form-item-gi :span="5" label="上游选择">
          <SelectUpstream v-model:upstream_id="rule.upstream_id">
          </SelectUpstream>
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
            <n-flex> 处理域名匹配规则 (为空则全部匹配, 规则不分先后) </n-flex>
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
                复制
              </n-button>
              <n-button :focusable="false" size="tiny" @click="import_rules">
                粘贴
              </n-button>
            </n-flex>
          </n-flex>
        </template>
        <n-dynamic-input v-model:value="rule.source" :on-create="onCreate">
          <template #create-button-default> 增加一条规则来源 </template>
          <template #default="{ value, index }">
            <n-flex style="flex: 1" :wrap="false">
              <n-button @click="changeCurrentRuleType(value, index)">
                <n-icon>
                  <ChangeCatalog />
                </n-icon>
              </n-button>
              <!-- <n-input
               
                v-model:value="value.key"
                placeholder="geo key"
                type="text"
              /> -->
              <DnsGeoSelect
                v-model:geo_key="value.key"
                v-model:geo_name="value.name"
                v-model:geo_inverse="value.inverse"
                v-model:attr_key="value.attribute_key"
                v-if="value.t === RuleSourceEnum.GeoKey"
              ></DnsGeoSelect>
              <n-flex v-else style="flex: 1">
                <n-input-group>
                  <n-select
                    style="width: 38%"
                    v-model:value="value.match_type"
                    :options="source_style"
                    placeholder="选择匹配方式"
                  />
                  <n-input
                    placeholder=""
                    v-model:value="value.value"
                    type="text"
                  />
                </n-input-group>
              </n-flex>
            </n-flex>
          </template>
        </n-dynamic-input>
      </n-form-item>
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
