<script setup lang="ts">
import { ref, computed, watch, CSSProperties } from "vue";
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

// Constants
const HEADER_COLOR = "rgb(72, 72, 78)";
const HANDLE_SIZE = 8;

// Store
const ptyStore = usePtyStore();
const { config, isConnected, keepAlive } = storeToRefs(ptyStore);

// Terminal instance
const drawerContentRef = ref<HTMLDivElement | null>(null);
const dockContentRef = ref<HTMLDivElement | null>(null);
let term: Terminal | null = null;
let fitAddon: FitAddon | null = null;

// UI State
const isFullScreen = ref(false);
const showSettings = ref(false);

// Draggable button state
const position = ref({ x: 0, y: 0 });
const isDragging = ref(false);
const dragStart = ref({ x: 0, y: 0 });
const initialPos = ref({ x: 0, y: 0 });

// Resize state
const isResizing = ref(false);
const startResizePos = ref(0);
const startResizeSize = ref(0);

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

const dockContainerStyle = computed<CSSProperties>(() => {
  const base = {
    position: "absolute" as const,
    zIndex: 1000,
    backgroundColor: "var(--n-color-modal)",
    display: "flex",
    flexDirection: "column" as const,
  };

  if (ptyStore.dockPosition === "bottom") {
    return {
      ...base,
      bottom: 0,
      left: "25px",
      right: 0,
      height: `${ptyStore.dockSize}px`,
    };
  }
  return {
    ...base,
    top: "40px",
    right: 0,
    bottom: 0,
    width: `${ptyStore.dockSize}px`,
    borderLeft: `2px solid ${HEADER_COLOR}`,
  };
});

const drawerPlacement = computed(() =>
  ptyStore.dockPosition === "right" ? "right" : "bottom",
);

const drawerSize = computed(() => {
  if (isFullScreen.value) return "100%";
  return ptyStore.dockPosition === "right" ? 500 : 400;
});

const resizeHandleStyle = computed<CSSProperties>(() => {
  const isBottom = ptyStore.dockPosition === "bottom";
  return {
    position: "absolute" as const,
    zIndex: 1001,
    cursor: isBottom ? "ns-resize" : "ew-resize",
    backgroundColor: isBottom ? "transparent" : undefined,
    ...(isBottom
      ? {
          top: `-${HANDLE_SIZE}px`,
          left: 0,
          right: 0,
          height: `${HANDLE_SIZE}px`,
        }
      : {
          left: `-${HANDLE_SIZE}px`,
          top: 0,
          bottom: 0,
          width: `${HANDLE_SIZE}px`,
        }),
  };
});

// --- Actions ---

function toggleDrawer() {
  if (!isDragging.value) ptyStore.toggleOpen();
}

function switchViewMode(mode: "float" | "dock") {
  if (ptyStore.viewMode === mode) return;
  cleanupTerminal();
  ptyStore.setViewMode(mode);
  remountTerminal();
}

function toggleDockPosition() {
  const newPos = ptyStore.dockPosition === "bottom" ? "right" : "bottom";
  if (ptyStore.viewMode === "dock" && ptyStore.isOpen) {
    cleanupTerminal();
    ptyStore.setDockPosition(newPos);
    remountTerminal();
  } else {
    ptyStore.setDockPosition(newPos);
  }
}

function toggleFullScreen() {
  isFullScreen.value = !isFullScreen.value;
  setTimeout(() => ptyStore.fit(), 300);
}

function reconnect() {
  ptyStore.disconnect();
  setTimeout(() => ptyStore.connect(), 100);
}

// --- Terminal Management ---

function cleanupTerminal() {
  if (term) {
    ptyStore.detachTerminal(term);
    term.dispose();
    term = null;
    fitAddon = null;
  }
}

function remountTerminal() {
  setTimeout(() => {
    if (ptyStore.isOpen) mountTerminal();
  }, 50);
}

function mountTerminal() {
  ptyStore.markRead();
  const target =
    ptyStore.viewMode === "float"
      ? drawerContentRef.value
      : dockContentRef.value;

  if (!target) return;
  while (target.firstChild) target.removeChild(target.firstChild);

  term = new Terminal({
    cols: 80,
    rows: 24,
    cursorBlink: true,
    fontFamily: 'Menlo, Monaco, "Courier New", monospace',
    allowProposedApi: true,
  });

  fitAddon = new FitAddon();
  term.loadAddon(fitAddon);
  term.open(target);
  ptyStore.attachTerminal(term, fitAddon);

  if (!ptyStore.isConnected) ptyStore.connect();
}

watch(
  () => [ptyStore.isOpen, ptyStore.viewMode],
  ([isOpen, mode]) => {
    if (isOpen && mode === "dock") setTimeout(mountTerminal, 50);
    else if (!isOpen && mode === "dock") cleanupTerminal();
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

function onResizeStart(e: MouseEvent) {
  isResizing.value = true;
  e.preventDefault();
  startResizeSize.value = ptyStore.dockSize;
  startResizePos.value =
    ptyStore.dockPosition === "bottom" ? e.clientY : e.clientX;
  document.addEventListener("mousemove", onResizeMove);
  document.addEventListener("mouseup", onResizeEnd);
}

function onResizeMove(e: MouseEvent) {
  if (!isResizing.value) return;
  const delta =
    ptyStore.dockPosition === "bottom"
      ? startResizePos.value - e.clientY
      : startResizePos.value - e.clientX;
  ptyStore.dockSize = Math.max(
    200,
    Math.min(1200, startResizeSize.value + delta),
  );
  ptyStore.fit();
}

function onResizeEnd() {
  isResizing.value = false;
  document.removeEventListener("mousemove", onResizeMove);
  document.removeEventListener("mouseup", onResizeEnd);
  ptyStore.fit();
}

// --- Drawer Hooks ---

function onAfterEnter() {
  if (ptyStore.viewMode === "float") mountTerminal();
}

function onAfterLeave() {
  if (ptyStore.viewMode === "float") cleanupTerminal();
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
    :placement="drawerPlacement"
    :width="drawerPlacement === 'right' ? drawerSize : undefined"
    :height="drawerPlacement === 'bottom' ? drawerSize : undefined"
    :min-width="drawerPlacement === 'right' ? 300 : undefined"
    :min-height="drawerPlacement === 'bottom' ? 200 : undefined"
    resizable
    :trap-focus="false"
    :block-scroll="false"
    to="body"
    display-directive="if"
    @after-enter="onAfterEnter"
    @after-leave="onAfterLeave"
  >
    <n-drawer-content
      closable
      body-content-style="padding: 0; display: flex; flex-direction: column;"
      header-class="terminal-header"
      :header-style="{ padding: '0 8px', height: '36px' }"
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
              {{ isConnected ? "Connected" : "Disconnected" }}
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
                  <span>Shell:</span>
                  <n-input
                    v-model:value="config.shell"
                    placeholder="bash"
                    size="tiny"
                    style="width: 100px"
                  />
                </n-flex>
                <n-flex justify="space-between" align="center">
                  <span>保持会话:</span>
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
                        >断开</n-button
                      >
                    </template>
                    确认断开连接?
                  </n-popconfirm>
                  <n-button type="primary" size="small" @click="reconnect"
                    >重连</n-button
                  >
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
                  @click="toggleDockPosition"
                >
                  <template #icon
                    ><n-icon :component="SwapHorizontalOutline"
                  /></template>
                </n-button>
              </template>
              {{
                ptyStore.dockPosition === "bottom" ? "切换到右侧" : "切换到底部"
              }}
            </n-tooltip>

            <n-tooltip trigger="hover">
              <template #trigger>
                <n-button
                  strong
                  secondary
                  type="primary"
                  size="tiny"
                  @click="switchViewMode('dock')"
                >
                  <template #icon><n-icon :component="PushOutline" /></template>
                </n-button>
              </template>
              停靠模式
            </n-tooltip>

            <n-divider vertical style="margin: 0 4px" />

            <n-button strong secondary size="tiny" @click="toggleFullScreen">
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
    :style="dockContainerStyle"
  >
    <div
      :style="resizeHandleStyle"
      class="resize-handle"
      @mousedown="onResizeStart"
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
            {{ isConnected ? "Connected" : "Disconnected" }}
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
                <span>Shell:</span>
                <n-input
                  v-model:value="config.shell"
                  placeholder="bash"
                  size="tiny"
                  style="width: 100px"
                />
              </n-flex>
              <n-flex justify="space-between" align="center">
                <span>保持会话:</span>
                <n-switch v-model:value="keepAlive" size="small" />
              </n-flex>
              <n-divider style="margin: 4px 0" />
              <n-flex justify="space-between">
                <n-popconfirm
                  @positive-click="ptyStore.disconnect"
                  :show-icon="false"
                >
                  <template #trigger>
                    <n-button type="error" size="small" :disabled="!isConnected"
                      >断开</n-button
                    >
                  </template>
                  确认断开连接?
                </n-popconfirm>
                <n-button type="primary" size="small" @click="reconnect"
                  >重连</n-button
                >
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
                @click="toggleDockPosition"
              >
                <template #icon
                  ><n-icon :component="SwapHorizontalOutline"
                /></template>
              </n-button>
            </template>
            {{
              ptyStore.dockPosition === "bottom" ? "切换到右侧" : "切换到底部"
            }}
          </n-tooltip>

          <n-divider vertical style="margin: 0 4px" />

          <n-tooltip trigger="hover">
            <template #trigger>
              <n-button
                strong
                secondary
                type="primary"
                size="tiny"
                @click="switchViewMode('float')"
              >
                <template #icon
                  ><n-icon :component="BrowsersOutline"
                /></template>
              </n-button>
            </template>
            悬浮模式
          </n-tooltip>

          <n-divider vertical style="margin: 0 4px" />

          <n-button
            strong
            secondary
            type="error"
            size="tiny"
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

.terminal-container {
  flex: 1;
  background-color: #000;
  overflow: hidden;
}

/* Unified header style */
.dock-header,
:deep(.terminal-header) {
  height: 36px;
  display: flex;
  align-items: center;
  padding: 0 8px;
  background-color: rgb(72, 72, 78) !important;
  border-bottom: 1px solid rgb(60, 60, 66) !important;
  color: #fff;
  flex-shrink: 0;
}

/* Resize handle - only visible in right mode */
.resize-handle {
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

.resize-handle[style*="ew-resize"]::after {
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
