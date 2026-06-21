<script lang="ts" setup>
import { get_static_nat_mappings_v6 } from "@/api/static_nat_mapping";
import type { StaticNatMappingV6Config } from "@landscape-router/types/api/schemas";
import { ref, onMounted } from "vue";
import { useI18n } from "vue-i18n";

const mapping_rules = ref<StaticNatMappingV6Config[]>([]);
const { t } = useI18n();

async function refresh_rules() {
  mapping_rules.value = await get_static_nat_mappings_v6();
}

onMounted(async () => {
  await refresh_rules();
});

const show_edit_modal = ref(false);
</script>
<template>
  <n-flex vertical style="flex: 1">
    <n-flex>
      <n-button @click="show_edit_modal = true">{{
        t("common.create")
      }}</n-button>
    </n-flex>
    <n-flex>
      <n-grid x-gap="12" y-gap="10" cols="1 600:2 1200:3 1600:3">
        <n-grid-item v-for="rule in mapping_rules" :key="rule.id">
          <StaticMappingV6Card @refresh="refresh_rules()" :rule="rule">
          </StaticMappingV6Card>
        </n-grid-item>
      </n-grid>
    </n-flex>

    <MappingEditV6Modal @refresh="refresh_rules" v-model:show="show_edit_modal">
    </MappingEditV6Modal>
  </n-flex>
</template>
