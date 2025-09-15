<script lang="ts" setup>
import { get_static_nat_mappings } from "@/api/static_nat_mapping";
import { StaticNatMappingConfig } from "@/rust_bindings/common/nat";
import { ref, onMounted } from "vue";

const mapping_rules = ref<StaticNatMappingConfig[]>([]);

async function refresh_rules() {
  mapping_rules.value = await get_static_nat_mappings();
}

onMounted(async () => {
  await refresh_rules();
});

const show_edit_modal = ref(false);
</script>
<template>
  <n-flex vertical style="flex: 1">
    <n-flex>
      <n-button @click="show_edit_modal = true">创建</n-button>
    </n-flex>
    <n-flex>
      <n-grid x-gap="12" y-gap="10" cols="1 600:2 1200:3 1600:3">
        <n-grid-item v-for="rule in mapping_rules" :key="rule.id">
          <StaticMappingCard @refresh="refresh_rules()" :rule="rule">
          </StaticMappingCard>
        </n-grid-item>
      </n-grid>
    </n-flex>

    <MappingEditModal @refresh="refresh_rules" v-model:show="show_edit_modal">
    </MappingEditModal>
  </n-flex>
</template>
