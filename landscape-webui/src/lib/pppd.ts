import type { PPPDConfig } from "@landscape-router/types/api/schemas";

const ADAY = 60 * 60 * 24;

export class PPPDServiceConfig {
  attach_iface_name: string;
  iface_name: string;
  enable: boolean;
  pppd_config: PPPDConfig;

  constructor(obj: {
    attach_iface_name: string;
    iface_name?: string;
    enable?: boolean;
    pppd_config?: PPPDConfig;
  }) {
    let date_str = (new Date().getTime() % ADAY).toString(36);
    this.attach_iface_name = obj.attach_iface_name;
    this.iface_name =
      obj?.iface_name ??
      `ppp-${obj.attach_iface_name}-${date_str}`.substring(0, 15);
    this.enable = obj?.enable ?? true;
    this.pppd_config = {
      default_route: obj.pppd_config?.default_route ?? true,
      peer_id: obj.pppd_config?.peer_id ?? "",
      password: obj.pppd_config?.password ?? "",
      ac: obj.pppd_config?.ac ?? null,
    };
  }
}
