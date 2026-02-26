<script setup lang="ts">
import {
  getDnsRule,
  addDnsRules,
} from "@landscape-router/types/api/dns-rules/dns-rules";
import {
  DnsRule,
  DomainMatchTypeEnum,
  FilterResultEnum,
  RuleSourceEnum,
} from "@/lib/dns";
import { useMessage } from "naive-ui";

import { ChangeCatalog } from "@vicons/carbon";
import { computed, onMounted } from "vue";
import { ref } from "vue";
import FlowMarkEdit from "@/components/flow/FlowMarkEdit.vue";
import type { RuleSource } from "@landscape-router/types/api/schemas";
import {
  copy_context_to_clipboard,
  read_context_from_clipboard,
} from "@/lib/common";
import { useI18n } from "vue-i18n";

type Props = {
  flow_id: number;
  rule_id?: string;
};

const props = defineProps<Props>();

const message = useMessage();
const { t } = useI18n();

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
    rule.value = new DnsRule(await getDnsRule(props.rule_id));
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
    message.warning(t("dns_editor.rule_edit.duplicate_priority_warning"));
    return;
  }

  if (
    typeof rule.value.bind_config.bind_addr4 === "string" &&
    rule.value.bind_config.bind_addr4.trim() === ""
  ) {
    rule.value.bind_config.bind_addr4 = undefined;
  }

  if (
    typeof rule.value.bind_config.bind_addr6 === "string" &&
    rule.value.bind_config.bind_addr6.trim() === ""
  ) {
    rule.value.bind_config.bind_addr6 = undefined;
  }

  try {
    commit_spin.value = true;
    await addDnsRules(rule.value);
    show.value = false;
  } catch (e: any) {
    // interceptor already shows error toast; e = { error_id, message, args }
  } finally {
    commit_spin.value = false;
  }
  emit("refresh");
}

const source_style = [
  {
    label: t("dns_editor.rule_edit.source_style_full"),
    value: DomainMatchTypeEnum.Full,
  },
  {
    label: t("dns_editor.rule_edit.source_style_domain"),
    value: DomainMatchTypeEnum.Domain,
  },
  {
    label: t("dns_editor.rule_edit.source_style_regex"),
    value: DomainMatchTypeEnum.Regex,
  },
  {
    label: t("dns_editor.rule_edit.source_style_plain"),
    value: DomainMatchTypeEnum.Plain,
  },
];

const filter_options = [
  {
    label: t("dns_editor.rule_edit.filter_unfilter"),
    value: FilterResultEnum.Unfilter,
  },
  {
    label: t("dns_editor.rule_edit.filter_ipv4"),
    value: FilterResultEnum.OnlyIPv4,
  },
  {
    label: t("dns_editor.rule_edit.filter_ipv6"),
    value: FilterResultEnum.OnlyIPv6,
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

async function append_import_rules() {
  try {
    let rules = JSON.parse(await read_context_from_clipboard());
    rule.value.source.unshift(...rules);
  } catch (e) {}
}

function add_by_quick_btn(match_type: DomainMatchTypeEnum | undefined) {
  if (match_type) {
    rule.value.source.unshift({
      t: "config",
      match_type,
      value: "",
    });
  } else {
    rule.value.source.unshift({ t: RuleSourceEnum.GeoKey, key: "" });
  }
}
</script>

<template>
  <n-modal
    v-model:show="show"
    style="width: 600px"
    class="custom-card"
    preset="card"
    :title="t('dns_editor.rule_edit.title')"
    @after-enter="enter"
    :bordered="false"
  >
    <!-- {{ isModified }} -->
    <n-form style="flex: 1" ref="formRef" :model="rule" :cols="5">
      <n-grid x-gap="10" :cols="5">
        <n-form-item-gi :label="t('dns_editor.rule_edit.priority')" :span="2">
          <n-input-number v-model:value="rule.index" clearable />
        </n-form-item-gi>
        <n-form-item-gi
          :label="t('dns_editor.rule_edit.enable')"
          :offset="1"
          :span="1"
        >
          <n-switch v-model:value="rule.enable">
            <template #checked>
              {{ t("dns_editor.rule_edit.enabled_yes") }}
            </template>
            <template #unchecked>
              {{ t("dns_editor.rule_edit.enabled_no") }}
            </template>
          </n-switch>
        </n-form-item-gi>

        <n-form-item-gi :span="2" :label="t('dns_editor.rule_edit.remark')">
          <n-input v-model:value="rule.name" type="text" />
        </n-form-item-gi>
        <n-form-item-gi
          :offset="1"
          :span="2"
          :label="t('dns_editor.rule_edit.filter_result')"
        >
          <!-- {{ rule }} -->
          <n-radio-group v-model:value="rule.filter" name="filter">
            <n-radio-button
              v-for="opt in filter_options"
              :key="opt.value"
              :value="opt.value"
              :label="opt.label"
            />
          </n-radio-group>
        </n-form-item-gi>

        <n-form-item-gi
          :span="5"
          :label="t('dns_editor.rule_edit.flow_action')"
        >
          <FlowMarkEdit v-model:mark="rule.mark"></FlowMarkEdit>
        </n-form-item-gi>

        <n-form-item-gi
          :span="2"
          :label="t('dns_editor.rule_edit.upstream_select')"
        >
          <SelectUpstream v-model:upstream_id="rule.upstream_id">
          </SelectUpstream>
        </n-form-item-gi>
        <!-- <n-form-item-gi :span="2" label="绑定本地 IPv4 (可选)">
          <n-input
            v-model:value="rule.bind_config.bind_addr4"
            clearable
          ></n-input>
        </n-form-item-gi>
        <n-form-item-gi :span="2" label="绑定本地 IPv6 (可选)">
          <n-input
            v-model:value="rule.bind_config.bind_addr6"
            clearable
          ></n-input>
        </n-form-item-gi> -->
      </n-grid>
      <n-form-item :show-feedback="false">
        <template #label>
          <n-flex
            align="center"
            justify="space-between"
            :wrap="false"
            @click.stop
          >
            <n-flex>
              {{ t("dns_editor.rule_edit.source_rules_title") }}
            </n-flex>
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
                {{ t("dns_editor.rule_edit.copy") }}
              </n-button>
              <n-button :focusable="false" size="tiny" @click="import_rules">
                {{ t("dns_editor.rule_edit.paste_replace") }}
              </n-button>
              <n-button
                :focusable="false"
                size="tiny"
                @click="append_import_rules"
              >
                {{ t("dns_editor.rule_edit.paste_append") }}
              </n-button>
            </n-flex>
          </n-flex>
        </template>
        <n-flex style="flex: 1" vertical>
          <n-flex style="padding: 5px 0px" justify="space-between">
            <n-button
              style="flex: 1"
              size="small"
              @click="add_by_quick_btn(undefined)"
            >
              {{ t("dns_editor.rule_edit.add_geo") }}
            </n-button>
            <n-button
              style="flex: 1"
              size="small"
              @click="add_by_quick_btn(DomainMatchTypeEnum.Full)"
            >
              {{ t("dns_editor.rule_edit.add_full") }}
            </n-button>
            <n-button
              style="flex: 1"
              size="small"
              @click="add_by_quick_btn(DomainMatchTypeEnum.Domain)"
            >
              {{ t("dns_editor.rule_edit.add_domain") }}
            </n-button>
            <n-button
              style="flex: 1"
              size="small"
              @click="add_by_quick_btn(DomainMatchTypeEnum.Plain)"
            >
              {{ t("dns_editor.rule_edit.add_plain") }}
            </n-button>
            <n-button
              style="flex: 1"
              size="small"
              @click="add_by_quick_btn(DomainMatchTypeEnum.Regex)"
            >
              {{ t("dns_editor.rule_edit.add_regex") }}
            </n-button>
          </n-flex>
          <n-scrollbar style="max-height: 280px">
            <n-dynamic-input
              item-style="padding-right: 15px"
              v-model:value="rule.source"
              :on-create="onCreate"
            >
              <template #create-button-default>
                {{ t("dns_editor.rule_edit.add_source_rule") }}
              </template>
              <template #default="{ value, index }">
                <n-flex :size="[10, 0]" style="flex: 1" :wrap="false">
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
                  <n-flex :size="[10, 0]" v-else style="flex: 1">
                    <n-input-group>
                      <n-select
                        style="width: 38%"
                        v-model:value="value.match_type"
                        :options="source_style"
                        :placeholder="
                          t('dns_editor.rule_edit.select_match_type')
                        "
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
          </n-scrollbar>
        </n-flex>
      </n-form-item>
    </n-form>
    <template #footer>
      <n-flex justify="space-between">
        <n-button @click="show = false">{{
          t("dns_editor.rule_edit.cancel")
        }}</n-button>
        <n-button
          :loading="commit_spin"
          @click="saveRule"
          :disabled="!isModified"
        >
          {{ t("dns_editor.rule_edit.save") }}
        </n-button>
      </n-flex>
    </template>
  </n-modal>
</template>
