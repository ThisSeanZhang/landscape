<script setup lang="ts">
import { computed } from "vue";
import { useRouter } from "vue-router";
import GeoRuleLink from "@/components/geo/GeoRuleLink.vue";
import { useThemeVars } from "naive-ui";
import {
  ArrowLeft,
  ArrowRight,
  Catalog,
  ChevronDown,
  ArrowUp,
  ArrowDown,
  ChartLine,
  Flash,
  Search,
} from "@vicons/carbon";
import { GlobeSearch24Regular } from "@vicons/fluent";
import type {
  ConnectHistoryStatus,
  ConnectRealtimeStatus,
} from "@landscape-router/types/api/schemas";
import { formatCount, formatPackets, formatRate, formatSize } from "@/lib/util";
import { useFrontEndStore } from "@/stores/front_end_config";
import { useEnrolledDeviceStore } from "@/stores/enrolled_device";
import { usePreferenceStore } from "@/stores/preference";

const props = defineProps<{
  item: ConnectHistoryStatus | ConnectRealtimeStatus;
  mode: "live" | "history";
  index: number;
  mobile?: boolean;
  expanded?: boolean;
}>();
const emit = defineEmits<{ chart: []; filter: []; toggle: [] }>();
const router = useRouter();
const devices = useEnrolledDeviceStore();
const frontEnd = useFrontEndStore();
const pref = usePreferenceStore();
const theme = useThemeVars();
const protocols: Record<number, string> = {
  1: "ICMP",
  6: "TCP",
  17: "UDP",
  58: "ICMPv6",
};

function endpoint(ip: string, port: number) {
  const name = devices.GET_NAME_WITH_FALLBACK(ip);
  return `${name.includes(":") ? `[${name}]` : name}:${frontEnd.MASK_PORT(port)}`;
}
const source = computed(() => endpoint(props.item.src_ip, props.item.src_port));
const destination = computed(() =>
  endpoint(props.item.dst_ip, props.item.dst_port),
);
const lastReport = computed(
  () => props.item.last_report_time || props.item.create_time_ms,
);
const traffic = computed(() => {
  const item = props.item;
  if ("egress_bps" in item) {
    return [
      {
        value: formatRate(item.egress_bps),
        packets: formatPackets(item.egress_pps),
      },
      {
        value: formatRate(item.ingress_bps),
        packets: formatPackets(item.ingress_pps),
      },
    ];
  }
  return [
    {
      value: formatSize(item.total_egress_bytes),
      packets: formatCount(item.total_egress_pkts) + " pkt",
    },
    {
      value: formatSize(item.total_ingress_bytes),
      packets: formatCount(item.total_ingress_pkts) + " pkt",
    },
  ];
});
function switchView() {
  const item = props.item;
  router.push({
    path:
      props.mode === "history" ? "/metrics/conn/live" : "/metrics/conn/history",
    query: {
      src_ip: item.src_ip,
      dst_ip: item.dst_ip,
      port_start: item.src_port,
      port_end: item.dst_port,
      flow_id: item.flow_id,
      ifindex: item.ifindex,
    },
  });
}
</script>

<template>
  <div
    :class="
      mobile
        ? ['connection-card', { expanded }]
        : ['connection-line', 'connection-row', { striped: index % 2 === 1 }]
    "
    :role="mobile ? 'article' : 'row'"
    :aria-rowindex="mobile ? undefined : index + 2"
  >
    <button
      v-if="mobile"
      class="summary"
      type="button"
      :aria-expanded="expanded"
      @click="emit('toggle')"
    >
      <span class="address-pair">
        <template
          v-for="(address, index) in [source, destination]"
          :key="index"
        >
          <span class="field-label">{{
            $t(
              index === 0
                ? "metric.connect.col.source"
                : "metric.connect.col.destination",
            )
          }}</span>
          <strong
            ><template v-for="(part, i) in address.split(':')" :key="i"
              ><template v-if="i">:<wbr /></template>{{ part }}</template
            ></strong
          >
        </template>
      </span>
      <n-icon class="chevron" :component="ChevronDown" />
      <span class="rates">
        <span
          v-for="(entry, i) in traffic"
          :key="i"
          :class="i === 0 ? 'upload' : 'download'"
        >
          <n-icon
            :aria-label="
              $t(
                i === 0
                  ? 'metric.connect.col.egress_rate'
                  : 'metric.connect.col.ingress_rate',
              )
            "
            role="img"
            :component="i === 0 ? ArrowUp : ArrowDown"
          />
          {{ entry.value }}
        </span>
      </span>
    </button>
    <div v-if="!mobile || expanded" class="row-fields">
      <div :role="mobile ? undefined : 'cell'">
        <span v-if="mobile" class="field-label">{{
          $t("metric.connect.col.last_report")
        }}</span>
        <n-tooltip>
          <template #trigger>
            <span class="stack">
              <n-time
                :time="lastReport"
                format="HH:mm:ss"
                :time-zone="pref.timezone"
              />
              <small v-if="mode === 'history'"
                ><n-time
                  :time="lastReport"
                  format="yyyy-MM-dd"
                  :time-zone="pref.timezone"
              /></small>
            </span>
          </template>
          {{ $t("metric.connect.filter.create_time") }}
          <n-time
            :time="item.create_time_ms"
            format="yyyy-MM-dd HH:mm:ss"
            :time-zone="pref.timezone"
          />
        </n-tooltip>
      </div>
      <div :role="mobile ? undefined : 'cell'">
        <span v-if="mobile" class="field-label">{{
          $t("metric.connect.filter.duration")
        }}</span>
        <DurationTime
          :seconds="Math.max(0, lastReport - item.create_time_ms) / 1000"
        />
      </div>
      <div v-if="mobile">
        <span class="field-label">{{
          $t("metric.connect.filter.create_time")
        }}</span>
        <n-time
          :time="item.create_time_ms"
          format="yyyy-MM-dd HH:mm:ss"
          :time-zone="pref.timezone"
        />
      </div>
      <div v-if="!mobile" role="cell" class="source">
        <span class="endpoint" :title="source">{{ source }}</span>
        <n-icon
          aria-hidden="true"
          :component="item.gress === 0 ? ArrowLeft : ArrowRight"
        />
      </div>
      <div v-if="!mobile" role="cell" class="endpoint" :title="destination">
        {{ destination }}
      </div>
      <div :role="mobile ? undefined : 'cell'" class="stack">
        <span v-if="mobile" class="field-label">{{
          $t("metric.connect.col.protocol_flow")
        }}</span>
        <span class="protocol">
          {{ protocols[item.l4_proto] ?? item.l4_proto }}
          <small>IPv{{ item.l3_proto === 0 ? 4 : 6 }}</small>
          <small
            v-if="item.gress === 0"
            class="inbound"
            :title="$t('metric.connect.filter.gress_ingress')"
            >IN</small
          >
        </span>
        <small>Flow {{ item.flow_id }} · IF {{ item.ifindex }}</small>
      </div>
      <div
        v-for="(entry, i) in traffic"
        :key="i"
        :role="mobile ? undefined : 'cell'"
        class="stack traffic"
      >
        <span v-if="mobile" class="field-label">{{
          $t(
            i === 0
              ? "metric.connect.col.egress_pps"
              : "metric.connect.col.ingress_pps",
          )
        }}</span>
        <strong v-else :class="i === 0 ? 'upload' : 'download'">{{
          entry.value
        }}</strong>
        <small>{{ entry.packets }}</small>
      </div>
      <div :role="mobile ? undefined : 'cell'" class="actions">
        <GeoRuleLink :target="{ ip: item.dst_ip }">
          <span v-if="mobile">GeoIP</span>
        </GeoRuleLink>
        <a
          :href="`https://edge-geo.y8955.workers.dev/${item.dst_ip}`"
          target="_blank"
          rel="noopener noreferrer"
          :title="$t('metric.connect.ip_stats.query_ip_ownership')"
          :aria-label="$t('metric.connect.ip_stats.query_ip_ownership')"
        >
          <n-icon :component="GlobeSearch24Regular" /><span v-if="mobile">{{
            $t("metric.connect.lookup")
          }}</span>
        </a>
        <button
          type="button"
          @click="emit('filter')"
          :title="$t('metric.connect.tip.precise_filter')"
          :aria-label="$t('metric.connect.tip.precise_filter')"
        >
          <n-icon :component="Search" /><span v-if="mobile">{{
            $t("common.filters")
          }}</span>
        </button>
        <button
          type="button"
          @click="switchView"
          :title="
            $t(
              mode === 'live'
                ? 'metric.connect.tip.view_history'
                : 'metric.connect.tip.view_live',
            )
          "
          :aria-label="
            $t(
              mode === 'live'
                ? 'metric.connect.tip.view_history'
                : 'metric.connect.tip.view_live',
            )
          "
        >
          <n-icon :component="mode === 'live' ? Catalog : Flash" /><span
            v-if="mobile"
            >{{ $t("metric.connect.switcher.history") }}</span
          >
        </button>
        <button
          type="button"
          @click="emit('chart')"
          :title="$t('metric.connect.tip.chart')"
          :aria-label="$t('metric.connect.tip.chart')"
        >
          <n-icon :component="ChartLine" /><span v-if="mobile">{{
            $t("metric.connect.chart_label")
          }}</span>
        </button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.row-fields {
  display: contents;
}
.connection-card {
  padding-bottom: 8px;
  font-variant-numeric: tabular-nums;
}
.summary {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 9px 8px;
  align-items: center;
  width: 100%;
  padding: 12px 14px;
  font: inherit;
  text-align: start;
  color: v-bind("theme.textColor1");
  cursor: pointer;
  background: v-bind("theme.cardColor");
  border: 1px solid v-bind("theme.dividerColor");
  border-radius: 9px;
}
.summary:focus-visible {
  outline: 2px solid v-bind("theme.primaryColor");
  outline-offset: -2px;
}
.address-pair {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr);
  align-items: baseline;
  gap: 4px 9px;
}
.address-pair strong {
  font: 500 13px/1.45 var(--font-mono);
  overflow-wrap: anywhere;
}
.field-label,
.chevron {
  color: v-bind("theme.textColor2");
}
.field-label {
  font-size: 12px;
}
.chevron {
  font-size: 18px;
}
.expanded .chevron {
  transform: rotate(180deg);
}
.rates {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  font-size: 12px;
  grid-column: 1/-1;
}
.rates > span {
  display: inline-flex;
  align-items: center;
  gap: 4px;
}
.expanded .summary {
  border-radius: 9px 9px 0 0;
}
.connection-card .row-fields {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px;
  padding: 12px 14px;
  background: v-bind("theme.cardColor");
  border: 1px solid v-bind("theme.dividerColor");
  border-top: 0;
  border-radius: 0 0 9px 9px;
}
.connection-card .row-fields > div:not(.actions) {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  min-width: 0;
  gap: 2px;
  font-size: 13px;
  overflow-wrap: anywhere;
}
.connection-card .actions {
  grid-column: 1/-1;
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 4px;
  border-top: 1px solid v-bind("theme.dividerColor");
  padding-top: 7px;
}
.connection-card .actions :is(a, button) {
  color: v-bind("theme.textColor2");
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  gap: 3px;
  width: 100%;
  min-height: 44px;
  font: inherit;
  text-decoration: none;
}
.connection-card .actions span {
  font-size: 11px;
}

.connection-row {
  height: var(--row-height);
  font-size: 13px;
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
}
.striped {
  background: v-bind("theme.tableColor");
}
.connection-row:hover,
.connection-row:focus-within {
  background: v-bind("theme.hoverColor");
}
.source {
  display: flex;
  min-width: 0;
  align-items: center;
  justify-content: space-between;
  gap: 6px;
}
.source .n-icon {
  flex: none;
  color: var(--muted);
}
.endpoint {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
}
.stack {
  display: flex;
  flex-direction: column;
  line-height: 1.35;
}
.protocol {
  display: flex;
  align-items: center;
  gap: 5px;
}
small {
  font-size: 11px;
  color: var(--muted);
}
.inbound {
  color: v-bind("theme.warningColor");
}
.traffic {
  align-items: flex-end;
}
.upload {
  color: var(--upload);
}
.download {
  color: var(--download);
}
.actions {
  display: flex;
  justify-content: center;
}
.actions :is(a, button) {
  box-sizing: border-box;
  display: inline-grid;
  place-items: center;
  width: 26px;
  height: 28px;
  padding: 0;
  border: 0;
  border-radius: 4px;
  background: transparent;
  color: var(--muted);
  font-size: 16px;
  cursor: pointer;
}
.actions :is(a, button):hover,
.actions :is(a, button):focus-visible {
  color: v-bind("theme.primaryColor");
  background: v-bind("theme.buttonColor2Hover");
}
</style>
