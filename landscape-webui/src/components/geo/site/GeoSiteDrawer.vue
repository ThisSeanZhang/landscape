<script setup lang="ts">
import { get_geo_site_configs, push_many_geo_site_rule } from "@/api/geo/site";
import {
  copy_context_to_clipboard,
  read_context_from_clipboard,
} from "@/lib/common";
import type { GeoSiteSourceConfig } from "landscape-types/api/schemas";
import { onMounted, ref } from "vue";

import { useMessage } from "naive-ui";
const message = useMessage();

const emit = defineEmits(["refresh", "refresh:keys"]);

const show = defineModel<boolean>("show", { required: true });
const show_create_modal = ref(false);

const configs = ref<any>();
onMounted(async () => {
  await refresh();
});

async function refresh() {
  configs.value = await get_geo_site_configs();
}

async function export_config() {
  let configs = await get_geo_site_configs();
  await copy_context_to_clipboard(
    message,
    JSON.stringify(
      configs,
      (key, value) => {
        if (key === "id") {
          return undefined;
        }
        return value;
      },
      2,
    ),
  );
}

async function import_rules() {
  try {
    let rules = JSON.parse(await read_context_from_clipboard());
    await push_many_geo_site_rule(rules);
    message.success("Import Success");
    await refresh();
  } catch (e) {}
}
</script>
<template>
  <n-drawer
    @after-enter="refresh"
    v-model:show="show"
    width="500px"
    placement="right"
  >
    <n-drawer-content title="Geo 配置来源" closable>
      <n-flex style="height: 100%" vertical>
        <n-flex>
          <n-button style="flex: 1" @click="show_create_modal = true">
            增加规则
          </n-button>
          <n-button style="flex: 1" @click="export_config">
            导出规则至剪贴板
          </n-button>
          <n-popconfirm @positive-click="import_rules">
            <template #trigger>
              <n-button style="flex: 1" @click=""> 从剪贴板导入规则 </n-button>
            </template>
            确定从剪贴板导入吗?
          </n-popconfirm>
        </n-flex>

        <n-scrollbar>
          <n-flex vertical>
            <GeoSiteItemCard
              @refresh="refresh"
              @refresh:keys="emit('refresh:keys')"
              v-for="rule in configs"
              :key="rule.index"
              :geo_site="rule"
            >
            </GeoSiteItemCard>
          </n-flex>
        </n-scrollbar>
      </n-flex>

      <GeoSiteEditModal
        :id="null"
        v-model:show="show_create_modal"
        @refresh="refresh"
      ></GeoSiteEditModal>
    </n-drawer-content>
  </n-drawer>
</template>
