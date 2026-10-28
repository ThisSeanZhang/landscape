import type {
  HealthCheckRuntime,
  PdRuntime,
  ServiceStatus,
  V4Runtime,
} from "@landscape-router/types/api/schemas";
import { describe, expect, it } from "vitest";
import {
  formatHealthRuntime,
  formatPdRuntime,
  formatServiceStatus,
  formatV4Runtime,
} from "@/lib/wan_runtime";

const t = (key: string, params?: Record<string, unknown>) => {
  const short = key.replace(/^topology\.panel\./, "");
  return params === undefined ? short : `${short} ${JSON.stringify(params)}`;
};

describe("formatV4Runtime", () => {
  it.each([
    [{ t: "idle" }, "runtime_v4_idle", "default"],
    [{ t: "idle_anchor" }, "runtime_v4_anchor", "default"],
    [{ t: "stopped" }, "runtime_v4_stopped", "default"],
    [
      { t: "static", ip: "1.2.3.4" },
      'runtime_v4_static {"ip":"1.2.3.4"}',
      "success",
    ],
  ])("maps %j", (rt, text, tone) => {
    expect(formatV4Runtime(rt as V4Runtime, t)).toEqual({ text, tone });
  });

  it("maps dhcp variants", () => {
    expect(
      formatV4Runtime(
        { t: "dhcp", discovering: { attempts: 3, backoff_rounds: 0 } },
        t,
      ),
    ).toEqual({
      text: 'runtime_v4_dhcp_discovering {"attempts":3}',
      tone: "info",
    });
    expect(
      formatV4Runtime({ t: "dhcp", requesting: { offered_ip: "10.0.0.2" } }, t),
    ).toEqual({
      text: 'runtime_v4_dhcp_requesting {"ip":"10.0.0.2"}',
      tone: "info",
    });
    expect(
      formatV4Runtime(
        {
          t: "dhcp",
          bound: {
            ip: "10.0.0.30",
            prefix: 24,
            lease_secs: 3600,
            renew_secs: 1800,
          },
        },
        t,
      ),
    ).toEqual({
      text: 'runtime_v4_dhcp_bound {"ip":"10.0.0.30","prefix":24}',
      tone: "success",
    });
    expect(
      formatV4Runtime({ t: "dhcp", renewing: { ip: "10.0.0.30" } }, t),
    ).toEqual({
      text: 'runtime_v4_dhcp_renewing {"ip":"10.0.0.30"}',
      tone: "warning",
    });
    expect(
      formatV4Runtime({ t: "dhcp", rebinding: { ip: "10.0.0.30" } }, t),
    ).toEqual({
      text: 'runtime_v4_dhcp_rebinding {"ip":"10.0.0.30"}',
      tone: "warning",
    });
  });

  it("maps pppoe variants including null-content unit states", () => {
    expect(
      formatV4Runtime({ t: "pppoe", dialing: null } as unknown as V4Runtime, t),
    ).toEqual({
      text: "runtime_v4_pppoe_dialing",
      tone: "info",
    });
    expect(
      formatV4Runtime(
        { t: "pppoe", negotiating: null } as unknown as V4Runtime,
        t,
      ),
    ).toEqual({
      text: "runtime_v4_pppoe_negotiating",
      tone: "info",
    });
    expect(
      formatV4Runtime(
        {
          t: "pppoe",
          online: {
            local_ip: "100.64.1.1",
            peer_ip: "100.64.1.2",
            session_id: 31,
            connected_at: 1_700_000_000_000,
          },
        },
        t,
      ),
    ).toEqual({
      text: "100.64.1.1",
      tone: "success",
    });
    expect(
      formatV4Runtime(
        { t: "pppoe", redial_backoff: { retry_count: 2, retry_in_secs: 5 } },
        t,
      ),
    ).toEqual({
      text: 'runtime_v4_pppoe_redial {"count":2,"secs":5}',
      tone: "warning",
    });
  });

  it("maps pppd variants including null-content unit states", () => {
    expect(
      formatV4Runtime({ t: "pppd", spawning: null } as unknown as V4Runtime, t),
    ).toEqual({
      text: "runtime_v4_pppd_spawning",
      tone: "info",
    });
    expect(
      formatV4Runtime(
        { t: "pppd", waiting_addr: { local: null, peer: null } },
        t,
      ),
    ).toEqual({ text: "runtime_v4_pppd_waiting_addr", tone: "info" });
    expect(
      formatV4Runtime(
        {
          t: "pppd",
          online: {
            local_ip: "10.1.1.1",
            peer_ip: "10.1.1.2",
            connected_at: 1_700_000_000_000,
          },
        },
        t,
      ),
    ).toEqual({
      text: "10.1.1.1",
      tone: "success",
    });
    expect(
      formatV4Runtime(
        { t: "pppd", restart_backoff: { failure_count: 1, retry_in_secs: 4 } },
        t,
      ),
    ).toEqual({
      text: 'runtime_v4_pppd_restart {"count":1,"secs":4}',
      tone: "warning",
    });
  });
});

describe("formatPdRuntime", () => {
  const lease = {
    prefix_ip: "2001:db8:1200::",
    prefix_len: 56,
    valid_secs: 7200,
    preferred_secs: 3600,
  };

  it("maps unit variants", () => {
    expect(formatPdRuntime("idle", t)).toEqual({
      text: "runtime_pd_idle",
      tone: "default",
    });
    expect(formatPdRuntime("soliciting", t)).toEqual({
      text: "runtime_pd_soliciting",
      tone: "info",
    });
    expect(formatPdRuntime("requesting", t)).toEqual({
      text: "runtime_pd_requesting",
      tone: "info",
    });
    expect(formatPdRuntime("stopped", t)).toEqual({
      text: "runtime_pd_stopped",
      tone: "default",
    });
  });

  it("maps lease variants", () => {
    expect(formatPdRuntime({ bound: lease } as PdRuntime, t)).toEqual({
      text: 'runtime_pd_bound {"prefix":"2001:db8:1200::","len":56}',
      tone: "success",
    });
    expect(formatPdRuntime({ renewing: lease } as PdRuntime, t)).toEqual({
      text: 'runtime_pd_renewing {"prefix":"2001:db8:1200::","len":56}',
      tone: "warning",
    });
    expect(formatPdRuntime({ rebinding: lease } as PdRuntime, t)).toEqual({
      text: 'runtime_pd_rebinding {"prefix":"2001:db8:1200::","len":56}',
      tone: "warning",
    });
  });
});

describe("formatServiceStatus", () => {
  it.each([
    [{ t: "staring" }, "runtime_svc_staring", "info"],
    [{ t: "running" }, "runtime_svc_running", "success"],
    [{ t: "stopping" }, "runtime_svc_stopping", "warning"],
    [{ t: "stop" }, "runtime_svc_stop", "default"],
    [{ t: "disabled" }, "runtime_svc_disabled", "default"],
    [{ t: "failed" }, "runtime_svc_failed", "error"],
  ])("maps %j", (status, text, tone) => {
    expect(formatServiceStatus(status as ServiceStatus, t)).toEqual({
      text,
      tone,
    });
  });
});

describe("formatHealthRuntime", () => {
  it("maps idle and stopped", () => {
    expect(formatHealthRuntime("idle", t)).toEqual({
      verdict: { text: "runtime_health_idle", tone: "default" },
      details: [],
    });
    expect(formatHealthRuntime("stopped", t)).toEqual({
      verdict: { text: "runtime_health_stopped", tone: "default" },
      details: [],
    });
  });

  it("maps running with per-target details and ewma", () => {
    expect(
      formatHealthRuntime(
        {
          running: {
            state: "healthy",
            rtt_ewma_ms: 5.25,
            probes: [
              { target: "1.1.1.1", rtt_ms: 5 },
              { target: "223.5.5.5", rtt_ms: null },
            ],
          },
        } as HealthCheckRuntime,
        t,
      ),
    ).toEqual({
      verdict: { text: "runtime_health_healthy", tone: "success" },
      details: [
        "1.1.1.1 · 5ms",
        "223.5.5.5 · runtime_health_timeout",
        'runtime_health_avg {"ms":5.3}',
      ],
    });
  });
});
