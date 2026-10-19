import type {
  HealthCheckRuntime,
  PdRuntime,
  ServiceStatus,
  V4Runtime,
  WanLinkHealthState,
} from "@landscape-router/types/api/schemas";

export type TagTone = "default" | "success" | "error" | "warning" | "info";

export type RuntimeT = (
  key: string,
  params?: Record<string, unknown>,
) => string;

export type RuntimeMask = (value: string) => string;

const identity_mask: RuntimeMask = (value) => value;

export interface RuntimeDisplay {
  text: string;
  tone: TagTone;
}

export function formatV4Runtime(
  rt: V4Runtime,
  t: RuntimeT,
  mask: RuntimeMask = identity_mask,
): RuntimeDisplay {
  switch (rt.t) {
    case "idle":
      return { text: t("topology.panel.runtime_v4_idle"), tone: "default" };
    case "idle_anchor":
      return { text: t("topology.panel.runtime_v4_anchor"), tone: "default" };
    case "stopped":
      return { text: t("topology.panel.runtime_v4_stopped"), tone: "default" };
    case "static":
      return {
        text: t("topology.panel.runtime_v4_static", { ip: mask(rt.ip) }),
        tone: "success",
      };
    case "dhcp":
      return formatDhcpV4(rt, t, mask);
    case "pppoe":
      return formatPppoe(rt, t, mask);
    case "pppd":
      return formatPppd(rt, t, mask);
  }
}

function formatDhcpV4(
  rt: V4Runtime & { t: "dhcp" },
  t: RuntimeT,
  mask: RuntimeMask,
): RuntimeDisplay {
  if ("discovering" in rt) {
    return {
      text: t("topology.panel.runtime_v4_dhcp_discovering", {
        attempts: rt.discovering.attempts,
      }),
      tone: "info",
    };
  }
  if ("requesting" in rt) {
    return {
      text: t("topology.panel.runtime_v4_dhcp_requesting", {
        ip: mask(rt.requesting.offered_ip),
      }),
      tone: "info",
    };
  }
  if ("bound" in rt) {
    return {
      text: t("topology.panel.runtime_v4_dhcp_bound", {
        ip: mask(rt.bound.ip),
        prefix: rt.bound.prefix,
      }),
      tone: "success",
    };
  }
  if ("renewing" in rt) {
    return {
      text: t("topology.panel.runtime_v4_dhcp_renewing", {
        ip: mask(rt.renewing.ip),
      }),
      tone: "warning",
    };
  }
  return {
    text: t("topology.panel.runtime_v4_dhcp_rebinding", {
      ip: mask(rt.rebinding.ip),
    }),
    tone: "warning",
  };
}

function formatPppoe(
  rt: V4Runtime,
  t: RuntimeT,
  mask: RuntimeMask,
): RuntimeDisplay {
  const v = rt as unknown as {
    online?: { local_ip: string; peer_ip: string; session_id: number };
    redial_backoff?: { retry_count: number; retry_in_secs: number };
    dialing?: null;
    negotiating?: null;
  };
  if (v.online !== undefined) {
    return {
      text: t("topology.panel.runtime_v4_pppoe_online", {
        local: mask(v.online.local_ip),
        peer: mask(v.online.peer_ip),
        session: `0x${v.online.session_id.toString(16)}`,
      }),
      tone: "success",
    };
  }
  if (v.redial_backoff !== undefined) {
    return {
      text: t("topology.panel.runtime_v4_pppoe_redial", {
        count: v.redial_backoff.retry_count,
        secs: v.redial_backoff.retry_in_secs,
      }),
      tone: "warning",
    };
  }
  if ("negotiating" in v) {
    return {
      text: t("topology.panel.runtime_v4_pppoe_negotiating"),
      tone: "info",
    };
  }
  return { text: t("topology.panel.runtime_v4_pppoe_dialing"), tone: "info" };
}

function formatPppd(
  rt: V4Runtime,
  t: RuntimeT,
  mask: RuntimeMask,
): RuntimeDisplay {
  const v = rt as unknown as {
    waiting_addr?: { local: string | null; peer: string | null };
    online?: { local_ip: string; peer_ip: string };
    restart_backoff?: { failure_count: number; retry_in_secs: number };
    spawning?: null;
  };
  if (v.online !== undefined) {
    return {
      text: t("topology.panel.runtime_v4_pppd_online", {
        local: mask(v.online.local_ip),
        peer: mask(v.online.peer_ip),
      }),
      tone: "success",
    };
  }
  if (v.restart_backoff !== undefined) {
    return {
      text: t("topology.panel.runtime_v4_pppd_restart", {
        count: v.restart_backoff.failure_count,
        secs: v.restart_backoff.retry_in_secs,
      }),
      tone: "warning",
    };
  }
  if (v.waiting_addr !== undefined) {
    return {
      text: t("topology.panel.runtime_v4_pppd_waiting_addr"),
      tone: "info",
    };
  }
  return { text: t("topology.panel.runtime_v4_pppd_spawning"), tone: "info" };
}

export function formatPdRuntime(
  rt: PdRuntime,
  t: RuntimeT,
  mask: RuntimeMask = identity_mask,
): RuntimeDisplay {
  if (rt === "idle") {
    return { text: t("topology.panel.runtime_pd_idle"), tone: "default" };
  }
  if (rt === "soliciting") {
    return { text: t("topology.panel.runtime_pd_soliciting"), tone: "info" };
  }
  if (rt === "requesting") {
    return { text: t("topology.panel.runtime_pd_requesting"), tone: "info" };
  }
  if (rt === "stopped") {
    return { text: t("topology.panel.runtime_pd_stopped"), tone: "default" };
  }
  if ("bound" in rt) {
    return {
      text: t("topology.panel.runtime_pd_bound", {
        prefix: mask(rt.bound.prefix_ip),
        len: rt.bound.prefix_len,
      }),
      tone: "success",
    };
  }
  if ("renewing" in rt) {
    return {
      text: t("topology.panel.runtime_pd_renewing", {
        prefix: mask(rt.renewing.prefix_ip),
        len: rt.renewing.prefix_len,
      }),
      tone: "warning",
    };
  }
  return {
    text: t("topology.panel.runtime_pd_rebinding", {
      prefix: mask(rt.rebinding.prefix_ip),
      len: rt.rebinding.prefix_len,
    }),
    tone: "warning",
  };
}

const SERVICE_STATUS_TABLE: Record<
  ServiceStatus["t"],
  { key: string; tone: TagTone }
> = {
  staring: { key: "runtime_svc_staring", tone: "info" },
  running: { key: "runtime_svc_running", tone: "success" },
  stopping: { key: "runtime_svc_stopping", tone: "warning" },
  stop: { key: "runtime_svc_stop", tone: "default" },
  disabled: { key: "runtime_svc_disabled", tone: "default" },
  failed: { key: "runtime_svc_failed", tone: "error" },
};

export function formatServiceStatus(
  status: ServiceStatus,
  t: RuntimeT,
): RuntimeDisplay {
  const entry = SERVICE_STATUS_TABLE[status.t];
  return { text: t(`topology.panel.${entry.key}`), tone: entry.tone };
}

export function formatHealthState(
  state: WanLinkHealthState,
  t: RuntimeT,
): RuntimeDisplay {
  switch (state) {
    case "healthy":
      return {
        text: t("topology.panel.runtime_health_healthy"),
        tone: "success",
      };
    case "unhealthy":
      return {
        text: t("topology.panel.runtime_health_unhealthy"),
        tone: "error",
      };
    default:
      return {
        text: t("topology.panel.runtime_health_unknown"),
        tone: "default",
      };
  }
}

export interface HealthRuntimeDisplay {
  verdict: RuntimeDisplay;
  details: string[];
}

export function formatHealthRuntime(
  rt: HealthCheckRuntime,
  t: RuntimeT,
  mask: RuntimeMask = identity_mask,
): HealthRuntimeDisplay {
  if (rt === "idle") {
    return {
      verdict: {
        text: t("topology.panel.runtime_health_idle"),
        tone: "default",
      },
      details: [],
    };
  }
  if (rt === "stopped") {
    return {
      verdict: {
        text: t("topology.panel.runtime_health_stopped"),
        tone: "default",
      },
      details: [],
    };
  }
  const verdict = formatHealthState(rt.running.state, t);
  const details = rt.running.probes.map((probe) =>
    probe.rtt_ms === null
      ? `${mask(probe.target)} · ${t("topology.panel.runtime_health_timeout")}`
      : `${mask(probe.target)} · ${probe.rtt_ms}ms`,
  );
  if (rt.running.rtt_ewma_ms !== null) {
    details.push(
      t("topology.panel.runtime_health_avg", {
        ms: Math.round(rt.running.rtt_ewma_ms * 10) / 10,
      }),
    );
  }
  return { verdict, details };
}
