<script lang="ts" setup>
import type { RuleSource } from "landscape-types/api/schemas";
import { DomainMatchTypeEnum, RuleSourceEnum } from "@/lib/dns";
import { useFrontEndStore } from "@/stores/front_end_config";

const frontEndStore = useFrontEndStore();
type Props = {
  source: RuleSource;
};

const props = defineProps<Props>();
</script>

<template>
  <n-tag v-if="source.t === RuleSourceEnum.Config">
    {{ source.match_type }}:{{ frontEndStore.MASK_INFO(source.value) }}
  </n-tag>
  <n-tag
    v-if="source.t === RuleSourceEnum.GeoKey"
    :type="source.inverse ? `warning` : ''"
  >
    {{ frontEndStore.MASK_INFO(source.name) }}/{{
      frontEndStore.MASK_INFO(source.key)
    }}{{
      source.attribute_key
        ? `@${frontEndStore.MASK_INFO(source.attribute_key)}`
        : ""
    }}
  </n-tag>
</template>
