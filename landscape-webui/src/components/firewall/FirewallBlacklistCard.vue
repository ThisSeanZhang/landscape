<script setup lang="ts">
import { computed, ref } from "vue";
import { Warning } from "@vicons/carbon";
import FirewallBlacklistEditModal from "./FirewallBlacklistEditModal.vue";
import BlacklistSourceExhibit from "./BlacklistSourceExhibit.vue";
import { delete_firewall_blacklist } from "@/api/firewall_blacklist";
import type { FirewallBlacklistConfig } from "@landscape-router/types/api/schemas";
import { useI18n } from "vue-i18n";

const rule = defineModel<FirewallBlacklistConfig>("rule", { required: true });
const { t } = useI18n();

const show_edit_modal = ref(false);

const emit = defineEmits(["refresh"]);

async function del() {
  if (rule.value.id) {
    await delete_firewall_blacklist(rule.value.id);
    emit("refresh");
  }
}

const title_name = computed(() =>
  rule.value.remark == null || rule.value.remark === ""
    ? t("common.no_remark")
    : rule.value.remark,
);
</script>
<template>
  <n-flex>
    <n-card size="small" style="flex: 1; min-width: 280px">
      <template #header>
        <StatusTitle :enable="rule.enable" :remark="title_name" />
      </template>
      <div style="height: 120px">
        <n-scrollbar v-if="rule.source.length > 0" style="height: 100%">
          <n-flex>
            <BlacklistSourceExhibit
              v-for="(item, index) in rule.source"
              :key="index"
              :source="item"
            />
          </n-flex>
        </n-scrollbar>
        <n-empty v-else description="无来源规则, 没有任何作用">
          <template #icon>
            <n-icon>
              <Warning />
            </n-icon>
          </template>
        </n-empty>
      </div>
      <template #header-extra>
        <n-flex>
          <n-button
            size="small"
            type="warning"
            secondary
            @click="show_edit_modal = true"
          >
            {{ t("common.edit") }}
          </n-button>
          <n-popconfirm @positive-click="del()">
            <template #trigger>
              <n-button size="small" type="error" secondary>
                {{ t("common.delete") }}
              </n-button>
            </template>
            {{ t("common.confirm_delete") }}
          </n-popconfirm>
        </n-flex>
      </template>
    </n-card>
    <FirewallBlacklistEditModal
      :id="rule.id ?? null"
      @refresh="emit('refresh')"
      v-model:show="show_edit_modal"
    />
  </n-flex>
</template>
