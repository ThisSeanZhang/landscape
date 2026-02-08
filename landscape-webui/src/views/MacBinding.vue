<script lang="ts" setup>
import { ref, onMounted } from "vue";
import { useI18n } from "vue-i18n";
import { get_mac_bindings } from "@/api/mac_binding";
import { IpMacBinding } from "landscape-types/common/mac_binding";
import MacBindingCard from "@/components/device/MacBindingCard.vue";
import MacBindingEditModal from "@/components/device/MacBindingEditModal.vue";
import { Add } from "@vicons/carbon";

const { t } = useI18n();
const bindings = ref<IpMacBinding[]>([]);
const loading = ref(false);

async function refresh() {
  loading.value = true;
  try {
    bindings.value = await get_mac_bindings();
  } catch (e) {
    console.error(e);
  } finally {
    loading.value = false;
  }
}

onMounted(async () => {
  await refresh();
});

const show_edit_modal = ref(false);
</script>

<template>
  <n-flex vertical style="flex: 1; padding: 24px">
    <n-flex align="center">
      <n-button type="primary" @click="show_edit_modal = true">
        <template #icon>
          <n-icon><Add /></n-icon>
        </template>
        新增设备
      </n-button>
    </n-flex>

    <n-divider />

    <n-spin :show="loading">
      <n-grid x-gap="12" y-gap="12" cols="1 600:2 1000:3 1400:4">
        <n-grid-item v-for="item in bindings" :key="item.id">
          <MacBindingCard :rule="item" @refresh="refresh" />
        </n-grid-item>
      </n-grid>

      <n-empty
        v-if="bindings?.length === 0 && !loading"
        description="暂无设备绑定信息"
        style="margin-top: 100px"
      >
        <template #extra>
          <n-button @click="show_edit_modal = true">立刻添加</n-button>
        </template>
      </n-empty>
    </n-spin>

    <MacBindingEditModal
      :rule_id="null"
      @refresh="refresh"
      v-model:show="show_edit_modal"
    />
  </n-flex>
</template>

<style scoped>
.n-h2 {
  font-weight: 600;
}
</style>
