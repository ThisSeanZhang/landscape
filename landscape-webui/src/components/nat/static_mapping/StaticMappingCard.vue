<script setup lang="ts">
import { delete_static_nat_mapping } from "@/api/static_nat_mapping";
import { StaticNatMappingConfig } from "landscape-types/common/nat";
import { ref } from "vue";
import { ArrowRight, Edit, TrashCan } from "@vicons/carbon";
import { useFrontEndStore } from "@/stores/front_end_config";
import { useMacBindingStore } from "@/stores/mac_binding";

const macBindingStore = useMacBindingStore();
import { usePreferenceStore } from "@/stores/preference";
const prefStore = usePreferenceStore();

const frontEndStore = useFrontEndStore();
const rule = defineModel<StaticNatMappingConfig>("rule", { required: true });

const show_edit_modal = ref(false);
const edit_focus_index = ref<number | undefined>(undefined);

const emit = defineEmits(["refresh"]);

function openEditModal(focusIndex?: number) {
  // Prevent opening modal if user is selecting text
  const selection = window.getSelection();
  if (selection && selection.toString().length > 0) {
    return;
  }

  edit_focus_index.value = focusIndex;
  show_edit_modal.value = true;
}

async function del() {
  if (rule.value.id) {
    await delete_static_nat_mapping(rule.value.id);
    emit("refresh");
  }
}

// Shorten IPv6 address by keeping only the last 3 segments (approx)
// e.g. 2001:0db8:85a3:0000:0000:8a2e:0370:7334 -> ...:8a2e:0370:7334
function formatIPv6(ip: string | null): string {
  if (!ip) return "";
  const masked = macBindingStore.GET_NAME_WITH_FALLBACK(ip);
  if (!masked) return "";

  // If it's a short address (e.g. ::1), just return it
  if (masked.length < 15) return `[${masked}]`;

  const parts = masked.split(":");
  if (parts.length > 4) {
    // Keep last 3 parts
    const suffix = parts.slice(-3).join(":");
    return `[...:${suffix}]`;
  }
  return `[${masked}]`;
}
</script>

<template>
  <div class="mapping-card-wrapper">
    <n-card
      size="small"
      class="mapping-card"
      :class="{ 'is-disabled': !rule.enable }"
      hoverable
      :bordered="false"
      embedded
      content-style="display: flex; flex-direction: column; height: 100%;"
      @click="openEditModal()"
    >
      <template #header>
        <StatusTitle :enable="rule.enable" :remark="rule.remark"></StatusTitle>
      </template>

      <template #header-extra>
        <n-flex size="small">
          <n-button
            secondary
            size="small"
            type="warning"
            @click.stop="openEditModal()"
          >
            编辑
          </n-button>

          <n-popconfirm @positive-click="del()">
            <template #trigger>
              <n-button secondary size="small" type="error" @click.stop>
                删除
              </n-button>
            </template>
            确定删除吗
          </n-popconfirm>
        </n-flex>
      </template>

      <!-- Top Section: Targets (Simulating Statistics) -->
      <n-grid :cols="2" :x-gap="12" style="margin-bottom: 4px">
        <!-- IPv4 Stat -->
        <n-gi>
          <div class="stat-box" :class="{ 'is-inactive': !rule.lan_ipv4 }">
            <div class="stat-label">IPv4 目标</div>
            <div class="stat-value-row">
              <template v-if="rule.lan_ipv4">
                <div class="stat-value">
                  {{ macBindingStore.GET_NAME_WITH_FALLBACK(rule.lan_ipv4) }}
                </div>
                <div class="stat-tags">
                  <n-tag
                    v-for="proto in rule.ipv4_l4_protocol"
                    :key="proto"
                    size="tiny"
                    :bordered="false"
                    :type="proto === 6 ? 'success' : 'info'"
                  >
                    {{ proto === 6 ? "TCP" : "UDP" }}
                  </n-tag>
                </div>
              </template>
              <template v-else>
                <div class="stat-value placeholder">-</div>
              </template>
            </div>
          </div>
        </n-gi>

        <!-- IPv6 Stat -->
        <n-gi>
          <div class="stat-box" :class="{ 'is-inactive': !rule.lan_ipv6 }">
            <div class="stat-label">IPv6 目标</div>
            <div class="stat-value-row">
              <template v-if="rule.lan_ipv6">
                <!-- Using shortened IPv6 display -->
                <div class="stat-value text-ellipsis" :title="rule.lan_ipv6">
                  {{ formatIPv6(rule.lan_ipv6) }}
                </div>
                <div class="stat-tags">
                  <n-tag
                    v-for="proto in rule.ipv6_l4_protocol"
                    :key="proto"
                    size="tiny"
                    :bordered="false"
                    :type="proto === 6 ? 'success' : 'info'"
                  >
                    {{ proto === 6 ? "TCP" : "UDP" }}
                  </n-tag>
                </div>
              </template>
              <template v-else>
                <div class="stat-value placeholder">-</div>
              </template>
            </div>
          </div>
        </n-gi>
      </n-grid>

      <n-divider style="margin: 8px 0 12px 0" />

      <!-- Bottom Section: Port Mappings (Fixed Height Wrapper) -->
      <div class="ports-container">
        <div class="section-label">
          端口映射 ({{ rule.mapping_pair_ports.length }})
        </div>
        <!-- Using a fixed height scrollbar to ensure consistent card height -->
        <n-scrollbar style="height: 100px; padding-right: 4px">
          <div class="ports-grid">
            <div
              v-for="(pair, index) in rule.mapping_pair_ports"
              :key="index"
              class="port-box"
              @click.stop="openEditModal(index)"
            >
              <span class="wan-port">{{
                frontEndStore.MASK_PORT(pair.wan_port.toString())
              }}</span>
              <n-icon :component="ArrowRight" class="arrow-icon" />
              <span class="lan-port">{{
                frontEndStore.MASK_PORT(pair.lan_port.toString())
              }}</span>
            </div>
          </div>
        </n-scrollbar>
      </div>

      <!-- Footer -->
      <div class="card-footer">
        <n-text depth="3" style="font-size: 12px">
          更新于
          <n-time
            :time="rule.update_at"
            format="yyyy-MM-dd HH:mm"
            :time-zone="prefStore.timezone"
          />
        </n-text>
      </div>
    </n-card>

    <MappingEditModal
      @refresh="emit('refresh')"
      :rule_id="rule.id"
      v-model:show="show_edit_modal"
      :initial-focus-index="edit_focus_index"
    >
    </MappingEditModal>
  </div>
</template>

<style scoped>
.mapping-card-wrapper {
  display: flex;
  flex: 1;
  min-width: 400px;
}

.mapping-card {
  flex: 1;
  border-radius: 4px;
  transition: all 0.2s ease-in-out;
  border: 1px solid transparent;
  cursor: pointer; /* Clickable */
}

.mapping-card.is-disabled {
  opacity: 0.7;
  border-color: var(--n-error-color);
}

/* Stat Box Styling (Like CPU Usage Stats) */
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
  font-size: 18px;
  font-weight: 500;
  line-height: 1.2;
  font-family: v-mono, SFMono-Regular, Menlo, monospace;
}

.stat-value.text-ellipsis {
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 100%;
}

.stat-value.placeholder {
  color: var(--n-text-color-disabled);
}

.stat-tags {
  display: flex;
  gap: 4px;
}

.stat-box.is-inactive .stat-label,
.stat-box.is-inactive .stat-value {
  color: var(--n-text-color-disabled);
}

/* Ports Grid (Like CPU Cores) */
.ports-container {
  /* Removed flex: 1 to respect fixed heights elsewhere if needed, 
     but keeping it block-level is fine. 
     The key is the scrollbar height. */
  display: flex;
  flex-direction: column;
}

.section-label {
  font-size: 12px;
  color: var(--n-text-color-3);
  margin-bottom: 8px;
}

.ports-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(115px, 1fr));
  gap: 8px;
  padding: 4px 2px; /* Top/Bottom padding for hover float, Side padding for safety */
}

.port-box {
  background-color: rgba(128, 128, 128, 0.08);
  border: 1px solid rgba(128, 128, 128, 0.15);
  border-radius: 4px;
  padding: 6px 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 13px;
  transition:
    transform 0.15s ease,
    box-shadow 0.15s ease,
    border-color 0.15s ease;
  user-select: none; /* Container not selectable */
  cursor: pointer;
  white-space: nowrap;
}

.port-box:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
  border-color: var(--n-primary-color);
  z-index: 1;
}

.wan-port {
  color: var(--n-warning-color);
  font-weight: 600;
  font-family: v-mono, SFMono-Regular, Menlo, monospace;
  user-select: text; /* Allow selection */
}

.lan-port {
  color: var(--n-info-color);
  font-weight: 600;
  font-family: v-mono, SFMono-Regular, Menlo, monospace;
  user-select: text; /* Allow selection */
}

/* Hover effect on ports only if not clicking card? 
   Actually, clicking a port box might not do anything specific, 
   but hovering is nice visual feedback. */
.port-box:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
  border-color: var(--n-primary-color);
  z-index: 1;
}

.wan-port {
  color: var(--n-warning-color);
  font-weight: 600;
  font-family: v-mono, SFMono-Regular, Menlo, monospace;
}

.lan-port {
  color: var(--n-info-color);
  font-weight: 600;
  font-family: v-mono, SFMono-Regular, Menlo, monospace;
}

.arrow-icon {
  color: var(--n-text-color-3);
  font-size: 12px;
  margin: 0 6px;
}

/* Footer */
.card-footer {
  margin-top: auto; /* Push to bottom */
  padding-top: 12px;
  text-align: right;
}

/* Dark Mode Adjustments */
:global(.n-config-provider--dark) .port-box {
  background-color: rgba(255, 255, 255, 0.04);
  border-color: rgba(255, 255, 255, 0.1);
}

:global(.n-config-provider--dark) .port-box:hover {
  border-color: var(--n-primary-color);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
}
</style>
