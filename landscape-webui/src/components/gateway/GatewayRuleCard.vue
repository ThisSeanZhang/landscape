<script setup lang="ts">
import { delete_gateway_rule } from "@/api/gateway";
import type { HttpUpstreamRuleConfig } from "@landscape-router/types/api/schemas";
import { ref } from "vue";
import { useI18n } from "vue-i18n";
import { usePreferenceStore } from "@/stores/preference";

const prefStore = usePreferenceStore();
const { t } = useI18n();
const rule = defineModel<HttpUpstreamRuleConfig>("rule", { required: true });

const show_edit_modal = ref(false);

const emit = defineEmits(["refresh"]);

function openEditModal() {
  const selection = window.getSelection();
  if (selection && selection.toString().length > 0) {
    return;
  }
  show_edit_modal.value = true;
}

async function del() {
  if (rule.value.id) {
    await delete_gateway_rule(rule.value.id);
    emit("refresh");
  }
}

function matchTypeLabel(): string {
  const mr = rule.value.match_rule;
  if (mr.t === "host") return t("gateway.type_host");
  if (mr.t === "path_prefix") return t("gateway.type_path_prefix");
  if (mr.t === "sni_proxy") return t("gateway.type_sni_proxy");
  return t("common.unknown");
}

function matchTypeTag(): "success" | "info" | "warning" {
  const mr = rule.value.match_rule;
  if (mr.t === "host") return "success";
  if (mr.t === "sni_proxy") return "warning";
  return "info";
}

function matchSummary(): string {
  const mr = rule.value.match_rule;
  if (mr.t === "host" || mr.t === "sni_proxy") {
    return mr.domains.join(", ");
  }
  if (mr.t === "path_prefix") {
    return mr.prefix;
  }
  return "";
}

function upstreamSummary(): string {
  const targets = rule.value.upstream.targets;
  if (targets.length === 0) return "-";
  if (targets.length === 1) {
    const t = targets[0];
    return `${t.address}:${t.port}${t.tls ? " (TLS)" : ""}`;
  }
  return `${targets.length} targets`;
}
</script>

<template>
  <div class="gateway-card-wrapper">
    <n-card
      size="small"
      class="gateway-card"
      :class="{ 'is-disabled': !rule.enable }"
      hoverable
      :bordered="false"
      embedded
      @click="openEditModal()"
    >
      <template #header>
        <StatusTitle :enable="rule.enable" :remark="rule.name" />
      </template>

      <template #header-extra>
        <n-flex size="small">
          <n-button
            secondary
            size="small"
            type="warning"
            @click.stop="openEditModal()"
          >
            {{ t("common.edit") }}
          </n-button>

          <n-popconfirm @positive-click="del()">
            <template #trigger>
              <n-button secondary size="small" type="error" @click.stop>
                {{ t("common.delete") }}
              </n-button>
            </template>
            {{ t("common.confirm_delete") }}
          </n-popconfirm>
        </n-flex>
      </template>

      <n-grid :cols="2" :x-gap="12" style="margin-bottom: 4px">
        <n-gi>
          <div class="stat-box">
            <div class="stat-label">{{ t("gateway.match_type") }}</div>
            <div class="stat-value-row">
              <n-tag :type="matchTypeTag()" size="small" :bordered="false">
                {{ matchTypeLabel() }}
              </n-tag>
            </div>
          </div>
        </n-gi>
        <n-gi>
          <div class="stat-box">
            <div class="stat-label">{{ t("gateway.upstream") }}</div>
            <div class="stat-value-row">
              <div class="stat-value mono" :title="upstreamSummary()">
                {{ upstreamSummary() }}
              </div>
            </div>
          </div>
        </n-gi>
      </n-grid>

      <n-divider style="margin: 8px 0 12px 0" />

      <div class="match-container">
        <div class="section-label">
          <template v-if="rule.match_rule.t === 'path_prefix'">
            {{ t("gateway.path_prefix") }}
          </template>
          <template v-else>
            {{ t("gateway.domains") }}
            ({{
              rule.match_rule.t === "host" || rule.match_rule.t === "sni_proxy"
                ? rule.match_rule.domains.length
                : 0
            }})
          </template>
        </div>
        <n-scrollbar style="max-height: 80px; padding-right: 4px">
          <template
            v-if="
              rule.match_rule.t === 'host' || rule.match_rule.t === 'sni_proxy'
            "
          >
            <n-flex :size="4" style="padding: 2px">
              <n-tag
                v-for="domain in rule.match_rule.domains"
                :key="domain"
                size="small"
                :bordered="false"
              >
                {{ domain }}
              </n-tag>
            </n-flex>
          </template>
          <template v-else-if="rule.match_rule.t === 'path_prefix'">
            <n-text code>{{ rule.match_rule.prefix }}</n-text>
          </template>
        </n-scrollbar>
      </div>

      <div class="card-footer">
        <n-text depth="3" style="font-size: 12px">
          {{ t("common.updated_at") }}
          <n-time
            :time="rule.update_at"
            format="yyyy-MM-dd HH:mm"
            :time-zone="prefStore.timezone"
          />
        </n-text>
      </div>
    </n-card>

    <GatewayRuleEditModal
      @refresh="emit('refresh')"
      :rule_id="rule.id"
      v-model:show="show_edit_modal"
    />
  </div>
</template>

<style scoped>
.gateway-card-wrapper {
  display: flex;
  flex: 1;
  min-width: 360px;
}

.gateway-card {
  flex: 1;
  border-radius: 4px;
  transition: all 0.2s ease-in-out;
  border: 1px solid transparent;
  cursor: pointer;
}

.gateway-card.is-disabled {
  opacity: 0.7;
  border-color: var(--n-error-color);
}

.stat-box {
  display: flex;
  flex-direction: column;
}

.stat-label {
  font-size: 12px;
  color: var(--n-text-color-3);
  margin-bottom: 2px;
}

.stat-value-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px;
  min-height: 24px;
}

.stat-value {
  font-size: 14px;
  font-weight: 500;
  line-height: 1.2;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 100%;
}

.stat-value.mono {
  font-family: v-mono, SFMono-Regular, Menlo, monospace;
}

.match-container {
  display: flex;
  flex-direction: column;
}

.section-label {
  font-size: 12px;
  color: var(--n-text-color-3);
  margin-bottom: 8px;
}

.card-footer {
  margin-top: auto;
  padding-top: 12px;
  text-align: right;
}
</style>
