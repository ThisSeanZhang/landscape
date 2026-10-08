import { Range } from "@/lib/common";
import type {
  WanLinkConfig,
  WanLinkKind,
  WanLinkV4Model,
} from "@landscape-router/types/api/schemas";

/** Placeholder for links that have not been persisted yet (server assigns). */
export const ZERO_UUID = "00000000-0000-0000-0000-000000000000";

export const DEFAULT_NAT_RANGE_START = 32768;
export const DEFAULT_NAT_RANGE_END = 65535;
export const DEFAULT_CLAMP_SIZE = 1492;
export const DEFAULT_EXPECTED_PD_LEN = 60;
export const DEFAULT_REQUESTED_MRU = 1492;

function default_nat_range(): Range {
  return new Range(DEFAULT_NAT_RANGE_START, DEFAULT_NAT_RANGE_END);
}

/**
 * Frontend wrapper around the generated `WanLinkConfig` with every section
 * defaulted, so section modals can bind directly. The WAN link itself is
 * invisible to users; the UI stays iface-centric.
 */
export class WanLink {
  id: string;
  name: string;
  attach_iface_name: string;
  kind: WanLinkKind;
  v4: { enable: boolean; model: WanLinkV4Model };
  pd: { enable: boolean; mac: string; expected_pd_len: number };
  nat: {
    enable: boolean;
    tcp_range: Range;
    udp_range: Range;
    icmp_in_range: Range;
  };
  firewall: { enable: boolean };
  mss: { enable: boolean; clamp_size: number };
  update_at?: number;

  constructor(obj?: Partial<WanLink> & { attach_iface_name?: string }) {
    this.id = obj?.id ?? ZERO_UUID;
    this.name = obj?.name ?? "";
    this.attach_iface_name = obj?.attach_iface_name ?? "";
    this.kind = obj?.kind ?? { t: "ethernet" };
    this.v4 = obj?.v4 ?? { enable: false, model: { t: "nothing" } };
    this.pd = obj?.pd ?? {
      enable: false,
      mac: "00:00:00:00:00:00",
      expected_pd_len: DEFAULT_EXPECTED_PD_LEN,
    };
    this.nat = {
      enable: obj?.nat?.enable ?? false,
      tcp_range: obj?.nat?.tcp_range ?? default_nat_range(),
      udp_range: obj?.nat?.udp_range ?? default_nat_range(),
      icmp_in_range: obj?.nat?.icmp_in_range ?? default_nat_range(),
    };
    this.firewall = obj?.firewall ?? { enable: false };
    this.mss = obj?.mss ?? { enable: false, clamp_size: DEFAULT_CLAMP_SIZE };
    this.update_at = obj?.update_at;
  }

  is_new(): boolean {
    return !this.id || this.id === ZERO_UUID;
  }

  /** The iface the per-link sections (nat/mss/fw/pd) operate on. */
  section_iface_name(): string {
    return this.kind.t === "pppd"
      ? this.kind.ppp_iface_name
      : this.attach_iface_name;
  }

  get ppp_iface_name(): string | undefined {
    return this.kind.t === "pppd" ? this.kind.ppp_iface_name : undefined;
  }
}

/** Default link for a WAN ethernet iface (created implicitly on first save). */
export function default_ethernet_link(attach_iface_name: string): WanLink {
  return new WanLink({ attach_iface_name });
}

/**
 * User-visible label: the link's remark name, falling back to its net iface.
 * Returns "" when the referenced link no longer exists (deleted link).
 */
export function link_label(
  links: WanLink[],
  link_id: string | null | undefined,
): string {
  const link = links.find((l) => l.id === link_id);
  if (link) {
    return link.name || link.section_iface_name();
  }
  return "";
}

export function wan_link_options(
  links: WanLink[],
): { label: string; value: string }[] {
  return links.map((l) => ({
    label: l.name || l.section_iface_name(),
    value: l.id,
  }));
}

const ADAY = 60 * 60 * 24;

/** Default pppd link (the "link icon" create flow). */
export function default_pppd_link(attach_iface_name: string): WanLink {
  const date_str = (new Date().getTime() % ADAY).toString(36);
  return new WanLink({
    attach_iface_name,
    kind: {
      t: "pppd",
      ppp_iface_name: `ppp-${attach_iface_name}-${date_str}`.substring(0, 15),
      peer_id: "",
      password: "",
      ac: null,
      plugin: "rp_pppoe",
    },
    v4: { enable: true, model: { t: "ipcp", default_router: true } },
  });
}

/** Build a `WanLink` from a raw server payload, filling defaults. */
export function wan_link_from_payload(payload: WanLinkConfig): WanLink {
  const raw = payload as unknown as Record<string, unknown>;
  return new WanLink({
    id: raw.id as string,
    name: (raw.name as string | undefined) ?? "",
    attach_iface_name: raw.attach_iface_name as string,
    kind: raw.kind as WanLinkKind | undefined,
    v4: raw.v4 as WanLink["v4"] | undefined,
    pd: {
      enable: (raw.pd as { enable?: boolean } | undefined)?.enable ?? false,
      mac: (raw.pd as { mac?: string } | undefined)?.mac ?? "00:00:00:00:00:00",
      expected_pd_len:
        (raw.pd as { expected_pd_len?: number | null } | undefined)
          ?.expected_pd_len ?? DEFAULT_EXPECTED_PD_LEN,
    },
    nat: {
      enable: (raw.nat as { enable?: boolean } | undefined)?.enable ?? false,
      tcp_range:
        (raw.nat as { tcp_range?: Range | null } | undefined)?.tcp_range ??
        default_nat_range(),
      udp_range:
        (raw.nat as { udp_range?: Range | null } | undefined)?.udp_range ??
        default_nat_range(),
      icmp_in_range:
        (raw.nat as { icmp_in_range?: Range | null } | undefined)
          ?.icmp_in_range ?? default_nat_range(),
    },
    firewall: {
      enable:
        (raw.firewall as { enable?: boolean } | undefined)?.enable ?? false,
    },
    mss: {
      enable: (raw.mss as { enable?: boolean } | undefined)?.enable ?? false,
      clamp_size:
        (raw.mss as { clamp_size?: number | null } | undefined)?.clamp_size ??
        DEFAULT_CLAMP_SIZE,
    },
    update_at: raw.update_at as number | undefined,
  });
}

// ── pppd modal form adapter (keeps the legacy form shape) ────────────

export class PppdLinkForm {
  attach_iface_name: string;
  iface_name: string;
  enable: boolean;
  pppd_config: {
    default_route: boolean;
    peer_id: string;
    password: string;
    ac: string | null;
    plugin: string;
  };

  constructor(obj: {
    attach_iface_name: string;
    iface_name?: string;
    enable?: boolean;
    pppd_config?: PppdLinkForm["pppd_config"];
  }) {
    this.attach_iface_name = obj.attach_iface_name;
    this.iface_name = obj.iface_name ?? "";
    this.enable = obj.enable ?? true;
    this.pppd_config = obj.pppd_config ?? {
      default_route: true,
      peer_id: "",
      password: "",
      ac: null,
      plugin: "rp_pppoe",
    };
  }
}

export function pppd_form_from_link(link: WanLink): PppdLinkForm {
  const kind = link.kind.t === "pppd" ? link.kind : undefined;
  const default_router =
    link.v4.model.t === "ipcp" ? !!link.v4.model.default_router : false;
  return new PppdLinkForm({
    attach_iface_name: link.attach_iface_name,
    iface_name: kind?.ppp_iface_name,
    enable: link.v4.enable,
    pppd_config: {
      default_route: default_router,
      peer_id: kind?.peer_id ?? "",
      password: kind?.password ?? "",
      ac: kind?.ac ?? null,
      plugin: kind?.plugin ?? "rp_pppoe",
    },
  });
}

export function apply_pppd_form(link: WanLink, form: PppdLinkForm): void {
  link.kind = {
    t: "pppd",
    ppp_iface_name: form.iface_name,
    peer_id: form.pppd_config.peer_id,
    password: form.pppd_config.password,
    ac: form.pppd_config.ac === "" ? null : form.pppd_config.ac,
    plugin: form.pppd_config.plugin as "pppoe" | "rp_pppoe",
  };
  link.v4 = {
    enable: form.enable,
    model: { t: "ipcp", default_router: form.pppd_config.default_route },
  };
}

// ── IP config modal form adapter (keeps the legacy form shape) ───────

export enum WanIpMode {
  Nothing = "nothing",
  Static = "static",
  PPPoE = "pppoe",
  DHCPClient = "dhcpclient",
}

export type IpFormModel =
  | { t: "nothing" }
  | {
      t: "static";
      ipv4: string;
      ipv4_mask: number;
      ipv6: string | null;
      default_router: boolean;
      default_router_ip: string;
    }
  | {
      t: "pppoe";
      username: string;
      password: string;
      mtu: number;
      ac_name: string | null;
      default_router: boolean;
    }
  | {
      t: "dhcpclient";
      hostname: string | null;
      default_router: boolean;
      custome_opts: [];
    };

export class IpConfigForm {
  iface_name: string;
  enable: boolean;
  ip_model: IpFormModel;
  update_at?: number;

  constructor(obj?: {
    iface_name?: string;
    enable?: boolean;
    ip_model?: IpFormModel;
    update_at?: number;
  }) {
    this.iface_name = obj?.iface_name ?? "";
    this.enable = obj?.enable ?? true;
    this.ip_model = obj?.ip_model ?? { t: "nothing" };
    this.update_at = obj?.update_at;
  }
}

export function ip_form_from_link(link: WanLink): IpConfigForm {
  if (link.kind.t === "pppoe_native") {
    const default_router =
      link.v4.model.t === "ipcp" ? !!link.v4.model.default_router : false;
    return new IpConfigForm({
      iface_name: link.attach_iface_name,
      enable: link.v4.enable,
      ip_model: {
        t: "pppoe",
        username: link.kind.username ?? "",
        password: link.kind.password ?? "",
        mtu: link.kind.requested_mru ?? DEFAULT_REQUESTED_MRU,
        ac_name: link.kind.ac_name ?? null,
        default_router,
      },
    });
  }

  const model = link.v4.model;
  switch (model.t) {
    case "static":
      return new IpConfigForm({
        iface_name: link.attach_iface_name,
        enable: link.v4.enable,
        ip_model: {
          t: "static",
          ipv4: model.ipv4 ?? "0.0.0.0",
          ipv4_mask: model.ipv4_mask ?? 24,
          ipv6: model.ipv6 ?? null,
          default_router: !!model.default_router,
          default_router_ip: model.default_router_ip ?? "0.0.0.0",
        },
      });
    case "dhcp_client":
      return new IpConfigForm({
        iface_name: link.attach_iface_name,
        enable: link.v4.enable,
        ip_model: {
          t: "dhcpclient",
          hostname: model.hostname ?? null,
          default_router: !!model.default_router,
          custome_opts: [],
        },
      });
    default:
      // nothing / ipcp on an ethernet link → nothing
      return new IpConfigForm({
        iface_name: link.attach_iface_name,
        enable: link.v4.enable,
        ip_model: { t: "nothing" },
      });
  }
}

export function apply_ip_form(link: WanLink, form: IpConfigForm): void {
  link.v4.enable = form.enable;
  switch (form.ip_model.t) {
    case "nothing":
      link.kind = { t: "ethernet" };
      link.v4.model = { t: "nothing" };
      break;
    case "static":
      link.kind = { t: "ethernet" };
      link.v4.model = {
        t: "static",
        ipv4: form.ip_model.ipv4,
        ipv4_mask: form.ip_model.ipv4_mask,
        ipv6: form.ip_model.ipv6,
        default_router: form.ip_model.default_router,
        default_router_ip: form.ip_model.default_router_ip,
      };
      break;
    case "dhcpclient":
      link.kind = { t: "ethernet" };
      link.v4.model = {
        t: "dhcp_client",
        hostname: form.ip_model.hostname,
        default_router: form.ip_model.default_router,
        custome_opts: [],
      };
      break;
    case "pppoe":
      link.kind = {
        t: "pppoe_native",
        username: form.ip_model.username,
        password: form.ip_model.password,
        requested_mru: form.ip_model.mtu || DEFAULT_REQUESTED_MRU,
        ac_name: form.ip_model.ac_name === "" ? null : form.ip_model.ac_name,
        lcp_echo_interval: null,
        redial_backoff_base_secs: null,
      };
      link.v4.model = {
        t: "ipcp",
        default_router: form.ip_model.default_router,
      };
      break;
  }
}
