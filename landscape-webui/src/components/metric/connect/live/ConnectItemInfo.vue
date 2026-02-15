<script setup lang="ts">
import {
  ConnectKey,
  ConnectRealtimeStatus,
} from "landscape-types/common/metric/connect";
import { useFrontEndStore } from "@/stores/front_end_config";
import { useRouter } from "vue-router";
import { ChartLine, ArrowUp, ArrowDown, Search, Catalog } from "@vicons/carbon";
import { mask_string } from "@/lib/common";
import { formatRate, formatPackets } from "@/lib/util";
import { useThemeVars } from "naive-ui";

const frontEndStore = useFrontEndStore();
const themeVars = useThemeVars();
const router = useRouter();
import { usePreferenceStore } from "@/stores/preference";
const prefStore = usePreferenceStore();

interface Props {
  conn: ConnectRealtimeStatus;
  index?: number;
}

const props = defineProps<Props>();

function l4_proto(value: number): string {
  if (value == 6) {
    return "TCP";
  } else if (value == 17) {
    return "UDP";
  } else if (value == 1) {
    return "ICMP";
  }
  return "Unknow";
}

function formatDuration(start: number, end: number): string {
  const diff = Math.max(0, end - start);
  const seconds = Math.floor(diff / 1000);

  if (seconds < 60) {
    return `${seconds}秒`;
  }

  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) {
    return `${minutes}分 ${seconds % 60}秒`;
  }

  const hours = Math.floor(minutes / 60);
  if (hours < 24) {
    return `${hours}小时 ${minutes % 60}分`;
  }

  const days = Math.floor(hours / 24);
  return `${days}天 ${hours % 24}小时`;
}

const lastActiveTime = (conn: ConnectRealtimeStatus) => {
  return conn.last_report_time || Date.now();
};

const goToHistory = (conn: ConnectRealtimeStatus) => {
  router.push({
    path: "/metric/conn/history",
    query: {
      src_ip: conn.src_ip,
      dst_ip: conn.dst_ip,
      port_start: conn.src_port,
      port_end: conn.dst_port,
      flow_id: conn.flow_id,
    },
  });
};

const emit = defineEmits([
  "show:chart",
  "search:tuple",
  "search:src",
  "search:dst",
]);
</script>

<template>
  <div
    class="box"
    :style="{
      backgroundColor:
        (index ?? 0) % 2 === 1 ? themeVars.tableColor : 'transparent',
    }"
  >
    <n-card
      size="small"
      :bordered="false"
      style="background: transparent"
      content-style="padding: 4px 12px"
    >
      <n-flex align="center" justify="space-between">
        <n-flex align="center">
          <n-flex align="center" style="width: 200px">
            <n-tooltip trigger="hover">
              <template #trigger>
                <div style="cursor: help">
                  <n-flex align="center" :wrap="false" size="small">
                    <span style="color: #888; font-size: 12px">{{
                      $t("metric.connect.filter.now")
                    }}</span>
                    <n-time
                      :time="lastActiveTime(conn)"
                      format="HH:mm:ss"
                      :time-zone="prefStore.timezone"
                    />
                    <n-divider vertical />
                    <span style="color: #888; font-size: 12px">
                      {{
                        formatDuration(
                          conn.create_time_ms,
                          lastActiveTime(conn),
                        )
                      }}
                    </span>
                  </n-flex>
                </div>
              </template>
              {{ $t("metric.connect.filter.create_time") }}:
              <n-time
                :time="conn.create_time_ms"
                format="yyyy-MM-dd HH:mm:ss"
                :time-zone="prefStore.timezone"
              />
            </n-tooltip>
          </n-flex>

          <n-flex style="width: 200px">
            <n-tag type="success" :bordered="false" size="small">
              {{ conn.l3_proto == 0 ? "IPV4" : "IPV6" }}
            </n-tag>
            <n-tag type="info" :bordered="false" size="small">
              {{ l4_proto(conn.l4_proto) }}
            </n-tag>

            <n-tag
              v-if="conn.flow_id != 0"
              type="info"
              :bordered="false"
              size="small"
            >
              FLOW: {{ conn.flow_id }}
            </n-tag>
          </n-flex>

          <n-flex
            align="center"
            style="width: 800px; font-variant-numeric: tabular-nums"
            size="small"
          >
            <span>
              {{
                `${frontEndStore.MASK_INFO(
                  conn.src_ip,
                )}:${frontEndStore.MASK_PORT(
                  conn.src_port,
                )} => ${frontEndStore.MASK_INFO(
                  conn.dst_ip,
                )}:${frontEndStore.MASK_PORT(conn.dst_port)}`
              }}
            </span>
            <n-tooltip trigger="hover">
              <template #trigger>
                <n-button
                  text
                  @click.stop="emit('search:tuple', conn)"
                  style="
                    font-size: 16px;
                    color: themeVars.infoColor;
                    opacity: 0.7;
                  "
                >
                  <n-icon><Search /></n-icon>
                </n-button>
              </template>
              {{ $t("metric.connect.tip.precise_filter") }}
            </n-tooltip>

            <n-tooltip trigger="hover">
              <template #trigger>
                <n-button
                  text
                  @click.stop="goToHistory(conn)"
                  style="
                    font-size: 16px;
                    color: themeVars.warningColor;
                    opacity: 0.7;
                  "
                >
                  <n-icon><Catalog /></n-icon>
                </n-button>
              </template>
              {{ $t("metric.connect.tip.view_history") }}
            </n-tooltip>
          </n-flex>

          <!-- 速率展示 -->
          <n-flex align="center" :wrap="false" style="gap: 24px">
            <!-- 出站 (Egress) -->
            <n-flex
              align="center"
              :wrap="false"
              size="small"
              style="width: 100px"
            >
              <n-icon
                :color="themeVars.infoColor"
                size="20"
                :style="{
                  filter: `drop-shadow(0 0 4px ${themeVars.infoColor}88)`,
                }"
              >
                <ArrowUp />
              </n-icon>
              <n-flex vertical :size="[-4, 0]" style="flex: 1">
                <span
                  style="
                    font-size: 13px;
                    font-weight: 600;
                    font-variant-numeric: tabular-nums;
                    line-height: 1.2;
                    white-space: nowrap;
                  "
                >
                  {{ formatRate(conn.egress_bps) }}
                </span>
                <span
                  style="
                    font-size: 10px;
                    color: #999;
                    font-variant-numeric: tabular-nums;
                    white-space: nowrap;
                  "
                >
                  {{ formatPackets(conn.egress_pps) }}
                </span>
              </n-flex>
            </n-flex>

            <!-- 进站 (Ingress) -->
            <n-flex
              align="center"
              :wrap="false"
              size="small"
              style="width: 100px"
            >
              <n-icon
                :color="themeVars.successColor"
                size="20"
                :style="{
                  filter: `drop-shadow(0 0 4px ${themeVars.successColor}88)`,
                }"
              >
                <ArrowDown />
              </n-icon>
              <n-flex vertical :size="[-4, 0]" style="flex: 1">
                <span
                  style="
                    font-size: 13px;
                    font-weight: 600;
                    font-variant-numeric: tabular-nums;
                    line-height: 1.2;
                    white-space: nowrap;
                  "
                >
                  {{ formatRate(conn.ingress_bps) }}
                </span>
                <span
                  style="
                    font-size: 10px;
                    color: #999;
                    font-variant-numeric: tabular-nums;
                    white-space: nowrap;
                  "
                >
                  {{ formatPackets(conn.ingress_pps) }}
                </span>
              </n-flex>
            </n-flex>
          </n-flex>
        </n-flex>

        <!-- 右侧区域：操作按钮 -->
        <n-flex align="center" :wrap="false">
          <!-- 图表按钮 -->
          <n-button
            :focusable="false"
            text
            style="font-size: 16px"
            @click="emit('show:chart', conn)"
          >
            <n-icon>
              <ChartLine />
            </n-icon>
          </n-button>
        </n-flex>
      </n-flex>
    </n-card>
  </div>
</template>

<style scoped>
.box {
  border: 2px solid transparent;
  transition: border-color 0.25s ease;
  margin-right: 12px;
}

.box:hover {
  border-color: #4fa3ff; /* 你想要的亮色 */
}
</style>
