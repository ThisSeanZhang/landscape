<script lang="ts" setup>
import { DomainMatchTypeEnum, RuleSourceEnum } from "@/lib/dns";
import type { RuleSource } from "@landscape-router/types/api/schemas";

import { ChangeCatalog } from "@vicons/carbon";
import { useI18n } from "vue-i18n";

const source = defineModel<RuleSource[]>("source", {
  default: [],
});
const { t } = useI18n();

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
    source.value[index] = {
      t: RuleSourceEnum.Config,
      match_type: DomainMatchTypeEnum.Full,
      value: value.key,
    };
  } else {
    source.value[index] = {
      t: RuleSourceEnum.GeoKey,
      key: value.value,
      name: "",
      inverse: false,
      attribute_key: null,
    };
  }
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

function add_by_quick_btn(match_type: DomainMatchTypeEnum | undefined) {
  if (match_type) {
    source.value.unshift({
      t: "config",
      match_type,
      value: "",
    });
  } else {
    source.value.unshift({
      t: RuleSourceEnum.GeoKey,
      key: "",
      name: "",
      inverse: false,
      attribute_key: null,
    });
  }
}
</script>
<template>
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
        v-model:value="source"
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
            >
            </DnsGeoSelect>
            <n-flex :size="[10, 0]" v-else style="flex: 1">
              <n-input-group>
                <n-select
                  style="width: 38%"
                  v-model:value="value.match_type"
                  :options="source_style"
                  :placeholder="t('dns_editor.rule_edit.select_match_type')"
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
</template>
