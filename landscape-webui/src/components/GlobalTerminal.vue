<script setup lang="ts">
import { ref, computed, watch, CSSProperties } from "vue";
import { useResizeObserver, useWindowSize } from "@vueuse/core";
import { useI18n } from "vue-i18n";
import {
  Terminal as TerminalIcon,
  Expand,
  Contract,
  BrowsersOutline,
  SwapHorizontalOutline,
  PushOutline,
  Close,
  SettingsOutline,
} from "@vicons/ionicons5";
import { usePtyStore } from "@/stores/pty";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { storeToRefs } from "pinia";
import "@xterm/xterm/css/xterm.css";

const HANDLE_SIZE = 8;

// Store
const ptyStore = usePtyStore();
const { config, isConnected, keepAlive } = storeToRefs(ptyStore);
const { t } = useI18n();

// Terminal instance
const drawerContentRef = ref<HTMLDivElement | null>(null);
const dockContentRef = ref<HTMLDivElement | null>(null);
const dockPanel = ref<HTMLDivElement | null>(null);

// UI State
const isFullScreen = ref(false);
const showSettings = ref(false);

// Draggable button state
const position = ref({ x: 0, y: 0 });
const isDragging = ref(false);
const dragStart = ref({ x: 0, y: 0 });
const initialPos = ref({ x: 0, y: 0 });

// Resize state
let startResizePos = 0;
let startResizeSize = 0;

// --- Computed Styles ---

const buttonType = computed(() => {
  if (ptyStore.hasUnread) return "warning";
  if (ptyStore.isConnected) return "primary";
  return "default";
});

const isVisible = computed(() => {
  if (ptyStore.isOpen) return false;
  if (ptyStore.hasUnread) return true;
  return keepAlive.value && isConnected.value;
});

const containerStyle = computed<CSSProperties>(() => {
  if (ptyStore.hasUnread && !ptyStore.isOpen) {
    return {
      top: "20px",
      left: "50%",
      transform: "translateX(-50%)",
      bottom: "auto",
      right: "auto",
      transition: "all 0.5s cubic-bezier(0.4, 0, 0.2, 1)",
      zIndex: 2001,
    };
  }
  return {
    bottom: "40px",
    left: "40px",
    transform: `translate(${position.value.x}px, ${position.value.y}px)`,
    transition: isDragging.value ? "none" : "transform 0.1s ease",
    cursor: isDragging.value ? "grabbing" : "grab",
    opacity: 0.9,
  };
});

const isBottom = computed(() => ptyStore.dockPosition === "bottom");
const { width: windowWidth, height: windowHeight } = useWindowSize({
  type: "visual",
});
const drawerSizes = ref({ right: 500, bottom: 400 });
const drawerMaxWidth = computed(() =>
  windowWidth.value <= 768
    ? Math.round(windowWidth.value * 0.9)
    : windowWidth.value,
);
const drawerWidth = computed(() =>
  isFullScreen.value
    ? "100%"
    : Math.min(drawerSizes.value.right, drawerMaxWidth.value),
);
const drawerHeight = computed(() =>
  isFullScreen.value
    ? "100%"
    : Math.min(drawerSizes.value.bottom, windowHeight.value),
);
const positionLabel = computed(() =>
  t(isBottom.value ? "terminal.switch_to_right" : "terminal.switch_to_bottom"),
);

// --- Actions ---

function toggleDrawer() {
  if (!isDragging.value) ptyStore.toggleOpen();
}

function switchViewMode(mode: "float" | "dock") {
  isFullScreen.value = false;
  ptyStore.setViewMode(mode);
}

function toggleDockPosition() {
  isFullScreen.value = false;
  ptyStore.setDockPosition(isBottom.value ? "right" : "bottom");
}

function reconnect() {
  ptyStore.disconnect();
  setTimeout(() => ptyStore.connect(), 100);
}

// --- Terminal Management ---

const terminalTarget = computed(() =>
  ptyStore.isOpen
    ? ptyStore.viewMode === "float"
      ? drawerContentRef.value
      : dockContentRef.value
    : null,
);

watch(
  terminalTarget,
  (target, _, onCleanup) => {
    if (!target) return;
    ptyStore.markRead();
    const term = new Terminal({
      cols: 80,
      rows: 24,
      cursorBlink: true,
      fontFamily:
        '"v-mono", SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace',
      allowProposedApi: true,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(target);
    ptyStore.attachTerminal(term, fit);
    ptyStore.connect();
    fit.fit();
    term.focus();
    onCleanup(() => {
      ptyStore.detachTerminal(term);
      term.dispose();
    });
  },
  { flush: "post" },
);

useResizeObserver(terminalTarget, () => ptyStore.fit());
watch(
  () => ptyStore.isOpen,
  (open) => {
    if (!open) isFullScreen.value = false;
  },
);

// --- Drag Handlers ---

function onMouseDown(e: MouseEvent) {
  if (ptyStore.hasUnread && !ptyStore.isOpen) return;
  isDragging.value = false;
  dragStart.value = { x: e.clientX, y: e.clientY };
  initialPos.value = { ...position.value };
  document.addEventListener("mousemove", onMouseMove);
  document.addEventListener("mouseup", onMouseUp);
}

function onMouseMove(e: MouseEvent) {
  const dx = e.clientX - dragStart.value.x;
  const dy = e.clientY - dragStart.value.y;
  if (!isDragging.value && (Math.abs(dx) > 3 || Math.abs(dy) > 3))
    isDragging.value = true;
  if (isDragging.value)
    position.value = { x: initialPos.value.x + dx, y: initialPos.value.y + dy };
}

function onMouseUp() {
  document.removeEventListener("mousemove", onMouseMove);
  document.removeEventListener("mouseup", onMouseUp);
  setTimeout(() => {
    isDragging.value = false;
  }, 0);
}

// --- Resize Handlers ---

function onResizeStart(event: PointerEvent) {
  if (event.button !== 0 || !dockPanel.value) return;
  const rect = dockPanel.value.getBoundingClientRect();
  startResizeSize = isBottom.value ? rect.height : rect.width;
  startResizePos = isBottom.value ? event.clientY : event.clientX;
  (event.currentTarget as HTMLElement).setPointerCapture(event.pointerId);
  event.preventDefault();
}

function onResizeMove(event: PointerEvent) {
  const handle = event.currentTarget as HTMLElement;
  const workspace = dockPanel.value?.parentElement;
  if (!workspace || !handle.hasPointerCapture(event.pointerId)) return;
  const coordinate = isBottom.value ? event.clientY : event.clientX;
  const available = isBottom.value
    ? workspace.clientHeight
    : workspace.clientWidth;
  const maxSize = Math.min(1200, available - HANDLE_SIZE);
  const requested = Math.round(startResizeSize + startResizePos - coordinate);
  ptyStore.dockSize = Math.max(200, Math.min(requested, maxSize));
}
</script>

<template>
  <!-- Floating Button -->
  <div
    v-if="isVisible"
    class="float-btn-container"
    :style="containerStyle"
    @mousedown="onMouseDown"
  >
    <n-badge
      :dot="ptyStore.hasUnread"
      processing
      type="warning"
      :offset="[-6, 6]"
    >
      <n-button
        circle
        class="float-btn"
        :type="buttonType"
        :class="{ 'breathing-btn': ptyStore.hasUnread }"
        @click="toggleDrawer"
      >
        <template #icon>
          <n-icon :component="TerminalIcon" size="32" />
        </template>
      </n-button>
    </n-badge>
  </div>

  <!-- Float Mode: Drawer -->
  <n-drawer
    v-if="ptyStore.viewMode === 'float'"
    v-model:show="ptyStore.isOpen"
    class="terminal-drawer"
    :placement="ptyStore.dockPosition"
    :width="drawerWidth"
    :height="drawerHeight"
    :min-width="Math.min(300, drawerMaxWidth)"
    :min-height="Math.min(200, windowHeight)"
    :max-width="drawerMaxWidth"
    :max-height="windowHeight"
    :on-update-width="(size: number) => (drawerSizes.right = size)"
    :on-update-height="(size: number) => (drawerSizes.bottom = size)"
    :resizable="!isFullScreen"
    :trap-focus="false"
    :block-scroll="false"
    to="body"
    display-directive="if"
  >
    <n-drawer-content
      closable
      body-content-style="height: 100%; padding: 0; display: flex; flex-direction: column;"
      header-class="terminal-header"
      :header-style="{
        padding: '4px 8px',
        minHeight: '36px',
        boxSizing: 'border-box',
      }"
    >
      <template #header>
        <n-flex justify="space-between" align="center" style="width: 100%">
          <n-flex align="center" size="small">
            <n-icon :component="TerminalIcon" />
            <span style="font-weight: 600; font-size: 13px">Web Shell</span>
            <n-divider vertical style="margin: 0 4px" />
            <n-tag
              :type="isConnected ? 'success' : 'error'"
              size="small"
              :bordered="false"
              style="height: 18px; padding: 0 4px"
            >
              {{
                isConnected
                  ? t("terminal.connected")
                  : t("terminal.disconnected")
              }}
            </n-tag>
          </n-flex>

          <n-flex size="small" align="center">
            <n-popover
              trigger="click"
              v-model:show="showSettings"
              placement="bottom-end"
            >
              <template #trigger>
                <n-button strong secondary type="default" size="tiny" circle>
                  <template #icon
                    ><n-icon :component="SettingsOutline"
                  /></template>
                </n-button>
              </template>
              <n-flex
                vertical
                size="small"
                style="padding: 4px; min-width: 200px"
              >
                <n-flex justify="space-between" align="center">
                  <span>{{ t("terminal.shell") }}:</span>
                  <n-input
                    v-model:value="config.shell"
                    placeholder="bash"
                    size="tiny"
                    style="width: 100px"
                  />
                </n-flex>
                <n-flex justify="space-between" align="center">
                  <span>{{ t("terminal.keep_alive") }}:</span>
                  <n-switch v-model:value="keepAlive" size="small" />
                </n-flex>
                <n-divider style="margin: 4px 0" />
                <n-flex justify="space-between">
                  <n-popconfirm
                    @positive-click="ptyStore.disconnect"
                    :show-icon="false"
                  >
                    <template #trigger>
                      <n-button
                        type="error"
                        size="small"
                        :disabled="!isConnected"
                        >{{ t("terminal.disconnect") }}</n-button
                      >
                    </template>
                    {{ t("terminal.disconnect_confirm") }}
                  </n-popconfirm>
                  <n-button type="primary" size="small" @click="reconnect">{{
                    t("terminal.reconnect")
                  }}</n-button>
                </n-flex>
              </n-flex>
            </n-popover>

            <n-divider vertical style="margin: 0 4px" />

            <n-tooltip trigger="hover">
              <template #trigger>
                <n-button
                  strong
                  secondary
                  type="default"
                  size="tiny"
                  :aria-label="positionLabel"
                  @click="toggleDockPosition"
                >
                  <template #icon
                    ><n-icon :component="SwapHorizontalOutline"
                  /></template>
                </n-button>
              </template>
              {{ positionLabel }}
            </n-tooltip>

            <n-tooltip trigger="hover">
              <template #trigger>
                <n-button
                  strong
                  secondary
                  type="primary"
                  size="tiny"
                  :aria-label="t('terminal.dock_mode')"
                  @click="switchViewMode('dock')"
                >
                  <template #icon><n-icon :component="PushOutline" /></template>
                </n-button>
              </template>
              {{ t("terminal.dock_mode") }}
            </n-tooltip>

            <n-divider vertical style="margin: 0 4px" />

            <n-button
              strong
              secondary
              size="tiny"
              :aria-label="
                t(
                  isFullScreen
                    ? 'terminal.exit_fullscreen'
                    : 'terminal.fullscreen',
                )
              "
              @click="isFullScreen = !isFullScreen"
            >
              <template #icon>
                <n-icon :component="isFullScreen ? Contract : Expand" />
              </template>
            </n-button>
          </n-flex>
        </n-flex>
      </template>

      <div ref="drawerContentRef" class="terminal-container"></div>
    </n-drawer-content>
  </n-drawer>

  <!-- Dock Mode: Split Panel -->
  <div
    v-if="ptyStore.viewMode === 'dock' && ptyStore.isOpen"
    ref="dockPanel"
    class="terminal-dock"
    :class="isBottom ? 'at-bottom' : 'at-right'"
    :style="{ '--dock-size': ptyStore.dockSize + 'px' }"
  >
    <div
      class="resize-handle"
      @pointerdown="onResizeStart"
      @pointermove="onResizeMove"
    ></div>

    <div class="dock-header">
      <n-flex justify="space-between" align="center" style="width: 100%">
        <n-flex align="center" size="small">
          <n-icon :component="TerminalIcon" />
          <span style="font-weight: 600; font-size: 13px">Web Shell</span>
          <n-divider vertical style="margin: 0 4px" />
          <n-tag
            :type="isConnected ? 'success' : 'error'"
            size="small"
            :bordered="false"
            style="height: 18px; padding: 0 4px"
          >
            {{
              isConnected ? t("terminal.connected") : t("terminal.disconnected")
            }}
          </n-tag>
        </n-flex>

        <n-flex size="small" align="center">
          <n-popover
            trigger="click"
            v-model:show="showSettings"
            placement="bottom-end"
          >
            <template #trigger>
              <n-button strong secondary type="default" size="tiny" circle>
                <template #icon
                  ><n-icon :component="SettingsOutline"
                /></template>
              </n-button>
            </template>
            <n-flex
              vertical
              size="small"
              style="padding: 4px; min-width: 200px"
            >
              <n-flex justify="space-between" align="center">
                <span>{{ t("terminal.shell") }}:</span>
                <n-input
                  v-model:value="config.shell"
                  placeholder="bash"
                  size="tiny"
                  style="width: 100px"
                />
              </n-flex>
              <n-flex justify="space-between" align="center">
                <span>{{ t("terminal.keep_alive") }}:</span>
                <n-switch v-model:value="keepAlive" size="small" />
              </n-flex>
              <n-divider style="margin: 4px 0" />
              <n-flex justify="space-between">
                <n-popconfirm
                  @positive-click="ptyStore.disconnect"
                  :show-icon="false"
                >
                  <template #trigger>
                    <n-button
                      type="error"
                      size="small"
                      :disabled="!isConnected"
                      >{{ t("terminal.disconnect") }}</n-button
                    >
                  </template>
                  {{ t("terminal.disconnect_confirm") }}
                </n-popconfirm>
                <n-button type="primary" size="small" @click="reconnect">{{
                  t("terminal.reconnect")
                }}</n-button>
              </n-flex>
            </n-flex>
          </n-popover>

          <n-divider vertical style="margin: 0 4px" />

          <n-tooltip trigger="hover">
            <template #trigger>
              <n-button
                strong
                secondary
                type="default"
                size="tiny"
                :aria-label="positionLabel"
                @click="toggleDockPosition"
              >
                <template #icon
                  ><n-icon :component="SwapHorizontalOutline"
                /></template>
              </n-button>
            </template>
            {{ positionLabel }}
          </n-tooltip>

          <n-divider vertical style="margin: 0 4px" />

          <n-tooltip trigger="hover">
            <template #trigger>
              <n-button
                strong
                secondary
                type="primary"
                size="tiny"
                :aria-label="t('terminal.float_mode')"
                @click="switchViewMode('float')"
              >
                <template #icon
                  ><n-icon :component="BrowsersOutline"
                /></template>
              </n-button>
            </template>
            {{ t("terminal.float_mode") }}
          </n-tooltip>

          <n-divider vertical style="margin: 0 4px" />

          <n-button
            strong
            secondary
            type="error"
            size="tiny"
            :aria-label="t('common.close')"
            @click="toggleDrawer"
          >
            <template #icon><n-icon :component="Close" /></template>
          </n-button>
        </n-flex>
      </n-flex>
    </div>

    <div ref="dockContentRef" class="terminal-container"></div>
  </div>
</template>

<style scoped>
.float-btn-container {
  position: fixed;
  z-index: 2000;
  touch-action: none;
}

.float-btn {
  width: 64px;
  height: 64px;
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.15);
  transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
}

.float-btn:hover {
  transform: scale(1.05);
  box-shadow: 0 12px 28px rgba(0, 0, 0, 0.2);
}

.breathing-btn {
  animation: breath 2s infinite ease-in-out;
}

.terminal-dock {
  position: relative;
  display: flex;
  flex-direction: column;
  flex: none;
  box-sizing: border-box;
  min-width: 0;
  min-height: 0;
  z-index: 1000;
  background: var(--n-color-modal);
}
.terminal-dock.at-bottom {
  height: var(--dock-size);
  max-height: calc(100% - 8px);
}
.terminal-dock.at-right {
  width: var(--dock-size);
  max-width: calc(100% - 8px);
  border-left: 2px solid rgb(72, 72, 78);
}
.terminal-container {
  flex: 1;
  min-width: 0;
  min-height: 0;
  background-color: #000;
  overflow: hidden;
}

/* Unified header style */
.dock-header,
:deep(.terminal-header) {
  min-height: 36px;
  box-sizing: border-box;
  display: flex;
  align-items: center;
  padding: 4px 8px;
  background-color: rgb(72, 72, 78) !important;
  border-bottom: 1px solid rgb(60, 60, 66) !important;
  color: #fff;
  flex-shrink: 0;
}

.at-bottom .resize-handle {
  inset: -8px 0 auto;
  height: 8px;
  cursor: ns-resize;
  background: transparent;
}
.at-right .resize-handle {
  inset: 0 auto 0 -8px;
  width: 8px;
  cursor: ew-resize;
}
.resize-handle {
  position: absolute;
  touch-action: none;
  user-select: none;
  display: flex;
  align-items: center;
  justify-content: center;
  background-color: rgb(72, 72, 78);
  transition: background-color 0.2s;
}

.resize-handle::after {
  content: "";
  background-color: rgb(120, 120, 126);
  border-radius: 2px;
}

.at-right .resize-handle::after {
  width: 4px;
  height: 60px;
}

.resize-handle:hover {
  background-color: var(--n-primary-color-suppl) !important;
}

.resize-handle:hover::after {
  background-color: var(--n-primary-color) !important;
}

@keyframes breath {
  0%,
  100% {
    transform: translateX(-50%) scale(1);
    box-shadow: 0 0 0 0 rgba(240, 160, 32, 0.7);
  }
  50% {
    transform: translateX(-50%) scale(1.1);
    box-shadow: 0 0 30px 10px rgba(240, 160, 32, 0);
  }
}
</style>
