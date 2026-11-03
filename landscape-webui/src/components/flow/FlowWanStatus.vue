<script setup lang="ts">
import { computed, onMounted, onUnmounted } from "vue";
import { useI18n } from "vue-i18n";
import { useFailoverStore } from "@/stores/failover";
import { flowWanPresentation } from "@/lib/flow_wan_status";
const props = defineProps<{ flowId: number }>();
const { t } = useI18n();
const store = useFailoverStore();
onMounted(store.subscribe);
onUnmounted(store.unsubscribe);
const presentation = computed(() =>
  flowWanPresentation(store.statuses, props.flowId),
);
function name(
  id: string | null | undefined,
  row: (typeof presentation.value.wanRows)[number],
) {
  if (!id) return t("flow.failover.no_exit");
  return row.candidates.find((c) => c.link_id === id)?.iface_name || id;
}
</script>
<template>
  <n-flex vertical size="small" style="width: 100%">
    <n-text v-if="store.unavailable" type="warning">{{
      t("flow.failover.status_unavailable")
    }}</n-text>
    <n-alert
      v-if="presentation.cleanup"
      :type="presentation.cleanup.router_policy_error ? 'error' : 'warning'"
      :show-icon="false"
    >
      {{
        t(
          presentation.cleanup.router_policy_error
            ? "flow.failover.router_cleanup_failed"
            : "flow.failover.router_cleanup_pending",
        )
      }}
      <div v-if="presentation.cleanup.router_policy_error">
        {{ presentation.cleanup.router_policy_error }}
      </div>
    </n-alert>
    <n-flex
      v-for="row in presentation.wanRows"
      :key="String(row.ipv6)"
      vertical
      size="small"
    >
      <n-alert
        v-if="row.trigger === 'link_state'"
        type="info"
        :show-icon="false"
        >{{ t("flow.failover.link_hint") }}</n-alert
      >
      <n-space align="center">
        <n-tag size="small">{{ row.ipv6 ? "IPv6" : "IPv4" }}</n-tag>
        <n-text strong
          >{{ t("flow.failover.active") }}:
          {{ row.active_iface_name || t("flow.failover.no_exit") }}</n-text
        >
        <n-text depth="3">{{
          row.trigger === "link_state" && row.reason === "healthy"
            ? t("flow.failover.link_online")
            : t(`flow.failover.reason.${row.reason}`)
        }}</n-text>
        <n-text v-if="row.retry_after_secs != null" depth="3">{{
          t("flow.failover.remaining", { seconds: row.retry_after_secs })
        }}</n-text>
      </n-space>
      <n-alert
        v-if="!row.router_policy_cleanup && row.router_policy_applied != null"
        :type="
          row.router_policy_applied
            ? 'success'
            : row.router_policy_error
              ? 'error'
              : 'warning'
        "
        :show-icon="false"
      >
        {{
          t(
            row.router_policy_applied
              ? "flow.failover.router_applied"
              : row.router_policy_error
                ? "flow.failover.router_failed"
                : "flow.failover.router_pending",
          )
        }}
        <div v-if="row.router_policy_error">{{ row.router_policy_error }}</div>
      </n-alert>
      <n-space>
        <n-tag
          v-for="candidate in row.candidates"
          :key="candidate.link_id"
          size="small"
          :type="
            !candidate.route_available ||
            (row.trigger !== 'link_state' && candidate.health === 'unhealthy')
              ? 'error'
              : row.trigger === 'link_state' || candidate.health === 'healthy'
                ? 'success'
                : 'warning'
          "
        >
          {{ candidate.iface_name || candidate.link_id }} ·
          <template
            v-if="row.trigger === 'link_state' && candidate.route_available"
            >{{ t("flow.failover.link_online") }} ·
          </template>
          {{
            t(
              `flow.failover.health.${candidate.route_available ? candidate.health : "disconnected"}`,
            )
          }}
        </n-tag>
      </n-space>
      <n-collapse v-if="row.history.length">
        <n-collapse-item
          :title="t('flow.failover.history')"
          :name="String(row.ipv6)"
        >
          <n-flex
            v-for="(event, index) in [...row.history].reverse()"
            :key="index"
            size="small"
          >
            <n-text depth="3">{{
              new Date(event.at_ms).toLocaleString()
            }}</n-text>
            <n-text
              >{{ name(event.previous, row) }} →
              {{ name(event.active, row) }}</n-text
            >
            <n-text depth="3">{{
              t(`flow.failover.cause.${event.cause}`)
            }}</n-text>
            <n-text depth="3">{{
              t(`flow.failover.${event.connection_policy}`)
            }}</n-text>
          </n-flex>
        </n-collapse-item>
      </n-collapse>
    </n-flex>
  </n-flex>
</template>
