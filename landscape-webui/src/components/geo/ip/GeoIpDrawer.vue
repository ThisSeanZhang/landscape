<script setup lang="ts">
import { get_geo_ip_configs, push_many_geo_ip_rule } from "@/api/geo/ip";
import {
  copy_context_to_clipboard,
  read_context_from_clipboard,
} from "@/lib/common";
import { onMounted, ref } from "vue";
import { useMessage } from "naive-ui";
import { useI18n } from "vue-i18n";
const message = useMessage();
const { t } = useI18n();

const emit = defineEmits(["refresh", "refresh:keys"]);

const show = defineModel<boolean>("show", { required: true });
const show_create_modal = ref(false);

const configs = ref<any>();
onMounted(async () => {
  await refresh();
});

async function refresh() {
  configs.value = await get_geo_ip_configs();
}

async function export_config() {
  let configs = await get_geo_ip_configs();
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
    await push_many_geo_ip_rule(rules);
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
    <n-drawer-content :title="t('geo.drawer.geo_ip_config_source')" closable>
      <n-flex style="height: 100%" vertical>
        <n-flex>
          <n-button style="flex: 1" @click="show_create_modal = true">
            {{ t("geo.drawer.add_rule") }}
          </n-button>
          <n-button style="flex: 1" @click="export_config">
            {{ t("geo.drawer.export_clipboard") }}
          </n-button>
          <n-popconfirm @positive-click="import_rules">
            <template #trigger>
              <n-button style="flex: 1" @click="">
                {{ t("geo.drawer.import_clipboard") }}
              </n-button>
            </template>
            {{ t("geo.drawer.confirm_import") }}
          </n-popconfirm>
        </n-flex>

        <n-scrollbar>
          <n-flex vertical>
            <GeoIpItemCard
              @refresh="refresh"
              @refresh:keys="emit('refresh:keys')"
              v-for="rule in configs"
              :key="rule.index"
              :geo_ip_source="rule"
            >
            </GeoIpItemCard>
          </n-flex>
        </n-scrollbar>
      </n-flex>

      <GeoIpEditModal
        :id="null"
        v-model:show="show_create_modal"
        @refresh="refresh"
      ></GeoIpEditModal>
    </n-drawer-content>
  </n-drawer>
</template>
