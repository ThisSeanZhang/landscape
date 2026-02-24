<script lang="ts" setup>
import { DomainMatchTypeEnum, RuleSourceEnum } from "@/lib/dns";
import type { RuleSource } from "@landscape-router/types/api/schemas";

import { ChangeCatalog } from "@vicons/carbon";

const source = defineModel<RuleSource[]>("source", {
  default: [],
});

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
        +地理关系库
      </n-button>
      <n-button
        style="flex: 1"
        size="small"
        @click="add_by_quick_btn(DomainMatchTypeEnum.Full)"
      >
        +精确匹配
      </n-button>
      <n-button
        style="flex: 1"
        size="small"
        @click="add_by_quick_btn(DomainMatchTypeEnum.Domain)"
      >
        +域名匹配
      </n-button>
      <n-button
        style="flex: 1"
        size="small"
        @click="add_by_quick_btn(DomainMatchTypeEnum.Plain)"
      >
        +关键词匹配
      </n-button>
      <n-button
        style="flex: 1"
        size="small"
        @click="add_by_quick_btn(DomainMatchTypeEnum.Regex)"
      >
        +正则匹配
      </n-button>
    </n-flex>
    <n-scrollbar style="max-height: 280px">
      <n-dynamic-input
        item-style="padding-right: 15px"
        v-model:value="source"
        :on-create="onCreate"
      >
        <template #create-button-default> 增加一条规则来源 </template>
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
    </n-scrollbar>
  </n-flex>
</template>
