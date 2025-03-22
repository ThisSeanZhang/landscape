export class FirewallServiceConfig {
  iface_name: string;
  enable: boolean;

  constructor(obj?: { iface_name: string; enable?: boolean }) {
    this.iface_name = obj?.iface_name ?? "";
    this.enable = obj?.enable ?? true;
  }
}
