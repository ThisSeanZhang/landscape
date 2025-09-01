<script lang="ts" setup>
import { DomainMatchTypeEnum, RuleSourceEnum } from "@/lib/dns";
import { RuleSource } from "@/rust_bindings/common/dns";

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
</script>
<template>
  <n-dynamic-input v-model:value="source" :on-create="onCreate">
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
        >
        </DnsGeoSelect>
        <n-flex v-else style="flex: 1">
          <n-input-group>
            <n-select
              style="width: 38%"
              v-model:value="value.match_type"
              :options="source_style"
              placeholder="选择匹配方式"
            />
            <n-input placeholder="" v-model:value="value.value" type="text" />
          </n-input-group>
        </n-flex>
      </n-flex>
    </template>
  </n-dynamic-input>
</template>
