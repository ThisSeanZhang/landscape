export class WifiServiceConfig {
  iface_name: string;
  enable: boolean;
  config: string;

  constructor(obj?: { iface_name: string; enable?: boolean; config?: string }) {
    this.iface_name = obj?.iface_name ?? "";
    this.enable = obj?.enable ?? true;
    this.config = obj?.config ?? "";
  }
}
