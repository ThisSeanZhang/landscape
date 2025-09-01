<script lang="ts" setup>
import { RuleSource } from "@/rust_bindings/common/dns";
import { DomainMatchTypeEnum, RuleSourceEnum } from "@/lib/dns";

type Props = {
  source: RuleSource;
};

const props = defineProps<Props>();
</script>

<template>
  <n-tag v-if="source.t === RuleSourceEnum.Config">
    {{ source.match_type }}:{{ source.value }}
  </n-tag>
  <n-tag
    v-if="source.t === RuleSourceEnum.GeoKey"
    :type="source.inverse ? `warning` : ''"
  >
    {{ source.name }}/{{ source.key
    }}{{ source.attribute_key ? `@${source.attribute_key}` : "" }}
  </n-tag>
</template>
