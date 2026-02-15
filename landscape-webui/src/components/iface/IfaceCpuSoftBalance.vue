<script setup lang="ts">
import { get_iface_cpu_balance, set_iface_cpu_balance } from "@/api/iface";
import { get_cpu_count } from "@/api/sys";
import { IfaceCpuSoftBalance } from "landscape-types/common/iface";
import { ref, computed } from "vue";

const show_model = defineModel<boolean>("show", { required: true });
const loading = ref(false);
const props = defineProps<{
  iface_name: string;
}>();

const balance_config = ref<IfaceCpuSoftBalance>({
  xps: "",
  rps: "",
});

const cpu_count = ref(0);
const xps_selected_cores = ref<Set<number>>(new Set());
const rps_selected_cores = ref<Set<number>>(new Set());

// 计算 CPU 核心选择数组
const available_cores = computed(() => {
  return Array.from({ length: cpu_count.value }, (_, i) => i);
});

// 将选中核心转换为位掩码数值
function coresToBitmask(selected_cores: Set<number>): string {
  if (selected_cores.size === 0) return "0";

  let bitmask = BigInt(0);
  selected_cores.forEach((core) => {
    bitmask |= BigInt(1) << BigInt(core);
  });
  return bitmask.toString(16);
}

// 将位掩码数值转换为选中核心
function bitmaskToCores(bitmask_str: string): Set<number> {
  const cores = new Set<number>();
  if (!bitmask_str) return cores;

  try {
    // 兼容可能带有 0x 前缀或纯 16 进制字符串
    const hex_str = bitmask_str.startsWith("0x")
      ? bitmask_str
      : "0x" + bitmask_str;
    const bitmask = BigInt(hex_str);

    if (bitmask === BigInt(0)) return cores;

    for (let i = 0; i < cpu_count.value; i++) {
      if (bitmask & (BigInt(1) << BigInt(i))) {
        cores.add(i);
      }
    }
  } catch (e) {
    console.error("解析位掩码失败:", e);
  }
  return cores;
}

// 切换核心选择状态
function toggleCore(core: number, type: "xps" | "rps") {
  const selected_cores =
    type === "xps" ? xps_selected_cores : rps_selected_cores;
  if (selected_cores.value.has(core)) {
    selected_cores.value.delete(core);
  } else {
    selected_cores.value.add(core);
  }
}

async function get_current_config() {
  try {
    // 获取 CPU 核心数
    cpu_count.value = await get_cpu_count();

    // 获取当前配置
    let data = await get_iface_cpu_balance(props.iface_name);
    if (data) {
      balance_config.value = data;

      // 解析当前配置到核心选择
      xps_selected_cores.value = bitmaskToCores(data.xps);
      rps_selected_cores.value = bitmaskToCores(data.rps);
    }
  } catch (error) {
    console.error("获取配置失败:", error);
  }
}

async function save_config() {
  try {
    loading.value = true;
    show_model.value = false;

    // 计算新的位掩码值
    const new_xps = coresToBitmask(xps_selected_cores.value);
    const new_rps = coresToBitmask(rps_selected_cores.value);

    const new_config = {
      xps: new_xps,
      rps: new_rps,
    };
    await set_iface_cpu_balance(props.iface_name, new_config);
  } catch (error) {
    console.error("保存配置失败:", error);
  } finally {
    loading.value = false;
  }
}

// 重置配置
function reset_config() {
  xps_selected_cores.value.clear();
  rps_selected_cores.value.clear();
}

// 设置 XPS 为 0
function setXpsToZero() {
  xps_selected_cores.value.clear();
}

// 设置 RPS 为 0
function setRpsToZero() {
  rps_selected_cores.value.clear();
}
</script>

<template>
  <n-modal
    :auto-focus="false"
    v-model:show="show_model"
    @after-enter="get_current_config"
  >
    <n-card
      style="width: 700px"
      title="配置网卡软负载"
      :bordered="false"
      size="small"
      role="dialog"
      aria-modal="true"
    >
      <n-flex vertical>
        <n-alert type="info">
          选择要处理网络队列的 CPU
          核心。选中多个核心可以将负载分布到不同核心，提升性能。
          <br />
          <strong>提示：</strong>可以点击下方的"设置为0"恢复默认
        </n-alert>

        <!-- CPU 核心选择区域 -->
        <div v-if="cpu_count > 0">
          <div class="core-selection-section">
            <h4>发送队列 (XPS) 核心选择</h4>
            <n-space wrap>
              <n-tag
                :type="xps_selected_cores.size === 0 ? 'warning' : 'default'"
                @click="setXpsToZero"
                checkable
                :checked="xps_selected_cores.size === 0"
              >
                设置为0
              </n-tag>
              <n-tag
                v-for="core in available_cores"
                :key="`xps-${core}`"
                :type="xps_selected_cores.has(core) ? 'primary' : 'default'"
                @click="toggleCore(core, 'xps')"
                checkable
                :checked="xps_selected_cores.has(core)"
              >
                CPU {{ core }}
              </n-tag>
            </n-space>
            <div class="selection-summary">
              <n-text depth="3">
                已选择:
                {{
                  Array.from(xps_selected_cores)
                    .sort((a, b) => a - b)
                    .join(", ") || "无"
                }}
                (位掩码: 0x{{ coresToBitmask(xps_selected_cores) }})
              </n-text>
            </div>
          </div>

          <n-divider />

          <div class="core-selection-section">
            <h4>接收队列 (RPS) 核心选择</h4>
            <n-space wrap>
              <n-tag
                :type="rps_selected_cores.size === 0 ? 'warning' : 'default'"
                @click="setRpsToZero"
                checkable
                :checked="rps_selected_cores.size === 0"
              >
                设置为0
              </n-tag>
              <n-tag
                v-for="core in available_cores"
                :key="`rps-${core}`"
                :type="rps_selected_cores.has(core) ? 'primary' : 'default'"
                @click="toggleCore(core, 'rps')"
                checkable
                :checked="rps_selected_cores.has(core)"
              >
                CPU {{ core }}
              </n-tag>
            </n-space>
            <div class="selection-summary">
              <n-text depth="3">
                已选择:
                {{
                  Array.from(rps_selected_cores)
                    .sort((a, b) => a - b)
                    .join(", ") || "无"
                }}
                (位掩码: 0x{{ coresToBitmask(rps_selected_cores) }})
              </n-text>
            </div>
          </div>
        </div>

        <div v-else><n-spin size="small" /> 正在获取 CPU 信息...</div>
      </n-flex>

      <template #footer>
        <n-flex justify="space-between" style="width: 100%">
          <n-button @click="reset_config"> 重置选择 </n-button>
          <n-space>
            <n-button @click="show_model = false"> 取消 </n-button>
            <n-button
              :loading="loading"
              round
              type="primary"
              @click="save_config"
            >
              保存配置
            </n-button>
          </n-space>
        </n-flex>
      </template>
    </n-card>
  </n-modal>
</template>

<style scoped>
.core-selection-section {
  margin-bottom: 20px;
}

.core-selection-section h4 {
  margin-bottom: 12px;
  font-size: 14px;
  font-weight: 600;
}

.selection-summary {
  margin-top: 8px;
  font-size: 12px;
}

/* 标签样式优化 */
:deep(.n-tag) {
  cursor: pointer;
  transition: all 0.2s ease;
  margin: 2px;
}

:deep(.n-tag:hover) {
  transform: translateY(-1px);
}

:deep(.n-tag.n-tag--checkable) {
  user-select: none;
}

/* 按钮样式优化 */
:deep(.n-button) {
  transition: all 0.2s ease;
}
</style>
