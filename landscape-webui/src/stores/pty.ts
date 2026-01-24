import { defineStore } from "pinia";
import { ref, watch } from "vue";
import { Terminal } from "@xterm/xterm";
import { SerializeAddon } from "@xterm/addon-serialize";
import { FitAddon } from "@xterm/addon-fit";
import { LANDSCAPE_TOKEN_KEY } from "@/lib/common";
import { LandscapePtyConfig, PtyOutMessage } from "landscape-types/common/pty";
import "@xterm/xterm/css/xterm.css";

export const usePtyStore = defineStore("pty", () => {
  // The "Master" terminal holds the state but never renders to DOM
  const masterTerminal = ref<Terminal | null>(null);
  const masterSerializeAddon = ref<SerializeAddon | null>(null);

  // The "Active" terminal is the one currently visible (if any)
  const activeTerminal = ref<Terminal | null>(null);
  const activeFitAddon = ref<FitAddon | null>(null);

  const socket = ref<WebSocket | null>(null);
  const isConnected = ref(false);
  const keepAlive = ref(true);
  const hasUnread = ref(false);

  // UI State - Load from LocalStorage if available
  const isOpen = ref(false);

  const savedViewMode = localStorage.getItem("landscape-pty-view-mode");
  const viewMode = ref<"float" | "dock">(
    savedViewMode === "float" ? "float" : "dock",
  );

  // Smart initial dock position based on screen aspect ratio
  function getSmartDockPosition(): "bottom" | "right" {
    const savedPos = localStorage.getItem("landscape-pty-dock-position");
    if (savedPos === "right" || savedPos === "bottom") {
      return savedPos;
    }
    // First time: choose based on screen dimensions
    // Wide screens (landscape) → right dock; Tall screens (portrait) → bottom dock
    const aspectRatio = window.innerWidth / window.innerHeight;
    return aspectRatio > 1.4 ? "right" : "bottom";
  }

  const dockPosition = ref<"bottom" | "right">(getSmartDockPosition());

  const savedDockSize = localStorage.getItem("landscape-pty-dock-size");
  const dockSize = ref(savedDockSize ? parseInt(savedDockSize) : 400);

  // Persistence Watchers
  watch(viewMode, (val) =>
    localStorage.setItem("landscape-pty-view-mode", val),
  );
  watch(dockPosition, (val) =>
    localStorage.setItem("landscape-pty-dock-position", val),
  );
  watch(dockSize, (val) =>
    localStorage.setItem("landscape-pty-dock-size", val.toString()),
  );

  const config = ref<LandscapePtyConfig>({
    shell: "bash",
    rows: 0,
    cols: 0,
    pixel_width: 0,
    pixel_height: 0,
  });

  function objToQuery(obj: any) {
    const token = localStorage.getItem(LANDSCAPE_TOKEN_KEY) ?? "";
    const query = Object.entries(obj)
      .map(
        ([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`,
      )
      .join("&");
    return query
      ? `${query}&token=${encodeURIComponent(token)}`
      : `token=${encodeURIComponent(token)}`;
  }

  function initMasterTerminal() {
    if (masterTerminal.value) return;

    // Headless terminal to keep state
    const term = new Terminal({
      cols: 129,
      rows: 33,
      allowProposedApi: true,
      scrollback: 5000, // Keep plenty of history
    });

    const serialize = new SerializeAddon();
    term.loadAddon(serialize);

    masterTerminal.value = term;
    masterSerializeAddon.value = serialize;
  }

  // Register a UI terminal to receive updates and sync state
  function attachTerminal(term: Terminal, fit: FitAddon) {
    activeTerminal.value = term;
    activeFitAddon.value = fit;
    hasUnread.value = false;

    // 1. Sync state from master
    if (masterSerializeAddon.value) {
      const history = masterSerializeAddon.value.serialize();
      term.write(history);
    }

    // 2. Setup input forwarding
    term.onData((data) => {
      if (socket.value && socket.value.readyState === WebSocket.OPEN) {
        socket.value.send(
          JSON.stringify({
            t: "data",
            data: Array.from(new TextEncoder().encode(data)),
          }),
        );
      }
    });

    // 3. Setup resize forwarding
    term.onResize((size) => {
      // Update master size too
      masterTerminal.value?.resize(size.cols, size.rows);

      if (!socket.value || socket.value.readyState !== WebSocket.OPEN) return;
      socket.value.send(
        JSON.stringify({
          t: "size",
          size: { ...size, pixel_width: 0, pixel_height: 0 },
        }),
      );
    });

    // Initial fit
    setTimeout(() => {
      fit.fit();
      term.focus();
    }, 50);
  }

  function detachTerminal(term: Terminal) {
    if (activeTerminal.value === term) {
      activeTerminal.value = null;
      activeFitAddon.value = null;
    }
  }

  function connect() {
    if (
      isConnected.value ||
      (socket.value && socket.value.readyState === WebSocket.OPEN)
    )
      return;

    initMasterTerminal();

    const url = `wss://${window.location.hostname}:${window.location.port}/api/sock/pty/create_session?${objToQuery(config.value)}`;
    const ws = new WebSocket(url);

    ws.onopen = () => {
      isConnected.value = true;
      // Prevent accidental page refresh
      window.addEventListener("beforeunload", preventUnload);
    };

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data) as PtyOutMessage;
        if (msg.t === "data") {
          const text = String.fromCharCode(...msg.data);

          // Write to Master (State)
          masterTerminal.value?.write(text);

          // Write to Active UI (View)
          if (activeTerminal.value) {
            activeTerminal.value.write(text);
          } else {
            // No active terminal means user isn't watching
            hasUnread.value = true;
          }
        } else if (msg.t === "exit") {
          const exitMsg = `\r\n[Process exited with code ${msg.msg}]\r\n`;
          masterTerminal.value?.write(exitMsg);
          activeTerminal.value?.write(exitMsg);
        }
      } catch (e) {
        console.error("Failed to parse PTY message", e);
      }
    };

    ws.onclose = () => {
      isConnected.value = false;
      socket.value = null;
      window.removeEventListener("beforeunload", preventUnload);
    };

    ws.onerror = () => {
      isConnected.value = false;
    };

    socket.value = ws;
  }

  function disconnect() {
    if (socket.value) {
      socket.value.close();
      socket.value = null;
    }
    isConnected.value = false;
    window.removeEventListener("beforeunload", preventUnload);
  }

  function preventUnload(e: BeforeUnloadEvent) {
    if (isConnected.value && keepAlive.value) {
      e.preventDefault();
      e.returnValue = "";
    }
  }

  function fit() {
    activeFitAddon.value?.fit();
  }

  function markRead() {
    hasUnread.value = false;
  }

  function toggleOpen() {
    isOpen.value = !isOpen.value;
  }

  // Refactored Actions for cleaner logic separation
  function setViewMode(mode: "float" | "dock") {
    viewMode.value = mode;
  }

  function setDockPosition(pos: "bottom" | "right") {
    dockPosition.value = pos;
  }

  return {
    isConnected,
    keepAlive,
    hasUnread,
    config,
    // UI State
    isOpen,
    viewMode,
    dockPosition,
    dockSize,
    // Actions
    connect,
    disconnect,
    attachTerminal,
    detachTerminal,
    fit,
    markRead,
    toggleOpen,
    setViewMode,
    setDockPosition,
  };
});
