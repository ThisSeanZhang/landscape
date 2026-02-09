<script setup lang="ts">
import {
  ConnectKey,
  ConnectHistoryStatus,
} from "landscape-types/common/metric/connect";
import { useFrontEndStore } from "@/stores/front_end_config";
import { useRouter } from "vue-router";
import { ChartLine, ArrowUp, ArrowDown, Search, Flash } from "@vicons/carbon";
import { mask_string } from "@/lib/common";
import { formatSize, formatCount } from "@/lib/util";
import { useThemeVars } from "naive-ui";
import { useMacBindingStore } from "@/stores/mac_binding";

const macBindingStore = useMacBindingStore();

const frontEndStore = useFrontEndStore();
const themeVars = useThemeVars();
const router = useRouter();
import { usePreferenceStore } from "@/stores/preference";
const prefStore = usePreferenceStore();

interface Props {
  history: ConnectHistoryStatus;
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

const goToLive = (history: ConnectHistoryStatus) => {
  router.push({
    path: "/metric/conn/live",
    query: {
      src_ip: history.src_ip,
      dst_ip: history.dst_ip,
      port_start: history.src_port.toString(),
      port_end: history.dst_port.toString(),
      flow_id: history.flow_id.toString(),
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
          <n-flex align="center" style="width: 160px">
            <n-flex vertical size="small">
              <n-time
                :time="history.last_report_time"
                format="yyyy-MM-dd HH:mm:ss"
                :time-zone="prefStore.timezone"
              />
              <div style="font-size: 10px; color: #888">
                <n-tooltip trigger="hover">
                  <template #trigger>
                    <span style="cursor: help; border-bottom: 1px dashed #888">
                      {{ $t("metric.connect.filter.duration") }}
                      {{
                        formatDuration(
                          history.create_time_ms,
                          history.last_report_time,
                        )
                      }}
                    </span>
                  </template>
                  {{ $t("metric.connect.filter.create_time") }}:
                  <n-time
                    :time="history.create_time_ms"
                    format="yyyy-MM-dd HH:mm:ss"
                    type="date"
                    :time-zone="prefStore.timezone"
                  />
                </n-tooltip>
              </div>
            </n-flex>
          </n-flex>

          <n-flex style="width: 200px">
            <n-tag type="success" :bordered="false" size="small">
              {{ history.l3_proto == 0 ? "IPV4" : "IPV6" }}
            </n-tag>
            <n-tag type="info" :bordered="false" size="small">
              {{ l4_proto(history.l4_proto) }}
            </n-tag>
          </n-flex>

          <n-flex
            align="center"
            style="width: 800px; font-variant-numeric: tabular-nums"
            size="small"
          >
            <span>
              {{
                `${macBindingStore.GET_NAME_WITH_FALLBACK(
                  history.src_ip,
                )}:${frontEndStore.MASK_PORT(
                  history.src_port,
                )} => ${macBindingStore.GET_NAME_WITH_FALLBACK(
                  history.dst_ip,
                )}:${frontEndStore.MASK_PORT(history.dst_port)}`
              }}
            </span>
            <n-tooltip trigger="hover">
              <template #trigger>
                <n-button
                  text
                  @click.stop="emit('search:tuple', history)"
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
                  @click.stop="goToLive(history)"
                  style="
                    font-size: 16px;
                    color: themeVars.successColor;
                    opacity: 0.7;
                  "
                >
                  <n-icon><Flash /></n-icon>
                </n-button>
              </template>
              {{ $t("metric.connect.tip.view_live") }}
            </n-tooltip>
          </n-flex>

          <!-- 累计总量展示 -->
          <n-flex align="center" :wrap="false" style="gap: 24px">
            <!-- 累计上行 -->
            <n-flex
              align="center"
              :wrap="false"
              size="small"
              style="width: 100px"
            >
              <n-icon :color="themeVars.infoColor" size="20">
                <ArrowUp />
              </n-icon>
              <n-flex vertical :size="[-4, 0]" style="flex: 1">
                <span
                  style="font-size: 13px; font-weight: 600; white-space: nowrap"
                >
                  {{ formatSize(history.total_egress_bytes) }}
                </span>
                <span style="font-size: 10px; color: #999; white-space: nowrap">
                  {{ formatCount(history.total_egress_pkts) }} pkt
                </span>
              </n-flex>
            </n-flex>

            <!-- 累计下行 -->
            <n-flex
              align="center"
              :wrap="false"
              size="small"
              style="width: 100px"
            >
              <n-icon :color="themeVars.successColor" size="20">
                <ArrowDown />
              </n-icon>
              <n-flex vertical :size="[-4, 0]" style="flex: 1">
                <span
                  style="font-size: 13px; font-weight: 600; white-space: nowrap"
                >
                  {{ formatSize(history.total_ingress_bytes) }}
                </span>
                <span style="font-size: 10px; color: #999; white-space: nowrap">
                  {{ formatCount(history.total_ingress_pkts) }} pkt
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
            @click="emit('show:chart', history)"
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
