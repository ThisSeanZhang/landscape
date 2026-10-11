<script setup lang="ts">
import {
  get_geo_site_configs,
  get_geo_site_tasks,
  push_many_geo_site_rule,
} from "@/api/geo/site";
import type { GeoTaskProgress } from "@landscape-router/types/api/schemas";
import {
  copy_context_to_clipboard,
  read_context_from_clipboard,
} from "@/lib/common";
import { computed, onMounted, onUnmounted, ref, watch } from "vue";

import { useMessage } from "naive-ui";
import { useI18n } from "vue-i18n";
const message = useMessage();
const { t } = useI18n();

const emit = defineEmits(["refresh", "refresh:keys"]);

const show = defineModel<boolean>("show", { required: true });
const show_create_modal = ref(false);

const configs = ref<any>();
const tasks = ref<Map<string, GeoTaskProgress>>(new Map());

const has_running_tasks = computed(() => tasks.value.size > 0);

onMounted(async () => {
  await refresh();
});

async function refresh() {
  configs.value = await get_geo_site_configs();
  await refresh_tasks();
}

// TODO: a task that fails quickly leaves no trace in the UI; the error is
// only visible in the server log.
async function refresh_tasks() {
  try {
    const list = await get_geo_site_tasks();
    const next = new Map(list.map((task) => [task.source_id, task]));
    const drained = tasks.value.size > 0 && next.size === 0;
    tasks.value = next;
    if (drained) {
      configs.value = await get_geo_site_configs();
      emit("refresh:keys");
    }
  } catch {
    // The axios interceptor already surfaces API errors; keep polling silent.
  }
}

let poll_timer: ReturnType<typeof setInterval> | null = null;

function start_polling() {
  if (poll_timer) return;
  poll_timer = setInterval(refresh_tasks, 5000);
}

function stop_polling() {
  if (poll_timer) {
    clearInterval(poll_timer);
    poll_timer = null;
  }
}

watch(has_running_tasks, (val) => {
  if (val) {
    start_polling();
  } else {
    stop_polling();
  }
});

watch(show, (val) => {
  if (!val) {
    stop_polling();
  } else if (has_running_tasks.value) {
    start_polling();
    refresh_tasks();
  }
});

onUnmounted(stop_polling);

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
    <n-drawer-content :title="t('geo.drawer.config_source')" closable>
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
            <GeoSiteItemCard
              @refresh="refresh"
              @refresh:keys="emit('refresh:keys')"
              @refresh:tasks="refresh_tasks"
              v-for="rule in configs"
              :key="rule.index"
              :geo_site="rule"
              :task="rule.id ? tasks.get(rule.id) : undefined"
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
