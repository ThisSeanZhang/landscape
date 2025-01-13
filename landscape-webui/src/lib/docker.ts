import { KeyValuePair } from "./common";
import { useThemeVars } from "naive-ui";

const LAND_REDIRECT_ID_KEY = "ld_red_id";
export class DockerContainerSummary {
  Created: number | undefined;
  Names: string[] | undefined;
  State: DockerContainerStatus | undefined;
  Image: string | undefined;
  Labels: Map<string, string> | undefined;

  constructor(obj?: {
    Created?: number;
    Names?: string[];
    State?: DockerContainerStatus;
    Image?: string;
    Labels?: any | undefined;
  }) {
    this.Created = obj?.Created;
    this.Names = obj?.Names;
    this.State = obj?.State;
    this.Image = obj?.Image;
    if (obj?.Labels !== undefined) {
      let map = new Map<string, string>();
      for (const [key, value] of Object.entries(obj?.Labels)) {
        map.set(key, value as string);
      }
      this.Labels = map;
    }
  }

  get_color() {
    const themeVars = useThemeVars();
    return this.State === DockerContainerStatus.running
      ? themeVars.value.successColor
      : "";
  }

  get_redirect_id(): string | undefined {
    if (this.Labels) {
      return this.Labels.get(LAND_REDIRECT_ID_KEY);
    }
  }
}

export class DockerImageSummary {
  Created: number | undefined;
  Labels: Map<string, string> | undefined;
  RepoTags: string[] | undefined;
  constructor(obj?: {
    Created?: number;
    Labels?: any | undefined;
    RepoTags: string[];
  }) {
    this.Created = obj?.Created;
    this.RepoTags = obj?.RepoTags;
    if (obj?.Labels !== undefined) {
      let map = new Map<string, string>();
      for (const [key, value] of Object.entries(obj?.Labels)) {
        map.set(key, value as string);
      }
      this.Labels = map;
    }
  }
}

export enum DockerContainerStatus {
  created = "created",
  restarting = "restarting",
  running = "running",
  removing = "removing",
  paused = "paused",
  exited = "exited",
  dead = "dead",
}

export class DockerBtnShow {
  start: boolean;
  stop: boolean;
  pause: boolean;
  unpause: boolean;
  remove: boolean;

  constructor(status: DockerContainerStatus | undefined) {
    this.start = false;
    this.stop = false;
    this.pause = false;
    this.unpause = false;
    this.remove = true;
    // 根据不同的状态设置按钮显示
    switch (status) {
      case DockerContainerStatus.created:
        this.start = true; // 容器是 created 时，可以启动
        this.remove = true; // 可以删除容器
        break;

      case DockerContainerStatus.running:
        this.stop = true; // 容器运行中时，可以停止
        this.pause = true; // 可以暂停容器
        this.remove = true; // 可以删除容器
        break;

      case DockerContainerStatus.paused:
        this.unpause = true; // 容器暂停时，可以恢复
        this.stop = true; // 也可以停止
        this.remove = true; // 可以删除容器
        break;

      case DockerContainerStatus.exited:
        this.start = true; // 容器停止后，可以重启
        this.remove = true; // 可以删除容器
        break;

      case DockerContainerStatus.restarting:
        this.stop = true; // 容器重启中时，可以停止
        this.remove = true; // 可以删除容器
        break;

      case DockerContainerStatus.dead:
        this.remove = true; // 死亡状态下，唯一可操作的就是删除
        break;

      case DockerContainerStatus.removing:
        // 容器在移除状态下，没有任何操作按钮
        this.remove = false; // 容器正在移除中，没有其他操作
        break;
    }
  }
}

export class DockerCmd {
  image_name: string;
  container_name: string;
  ports: KeyValuePair[];
  environment: KeyValuePair[];
  volumes: KeyValuePair[];
  labels: KeyValuePair[];

  constructor(obj: {
    image_name?: string;
    container_name?: string;
    ports?: KeyValuePair[];
    environment?: KeyValuePair[];
    volumes?: KeyValuePair[];
    labels?: KeyValuePair[];
  }) {
    this.image_name = obj.image_name ?? "";
    this.container_name = obj.container_name ?? "";
    this.ports = obj.ports ?? [];
    this.environment = obj.environment ?? [];
    this.volumes = obj.volumes ?? [];
    this.labels = obj.labels ?? [];
  }
}

// export class HealthConfig {
//   Test: string[] | undefined;
//   Interval: number | undefined;
//   Timeout: number | undefined;
//   Retries: number | undefined;
//   StartPeriod: number | undefined;
//   StartInterval: number | undefined;

//   constructor(obj?: {
//     Test?: string[];
//     Interval?: number;
//     Timeout?: number;
//     Retries?: number;
//     StartPeriod?: number;
//     StartInterval?: number;
//   }) {
//     this.Test = obj?.Test;
//     this.Interval = obj?.Interval;
//     this.Timeout = obj?.Timeout;
//     this.Retries = obj?.Retries;
//     this.StartPeriod = obj?.StartPeriod;
//     this.StartInterval = obj?.StartInterval;
//   }
// }

// export class EndpointSettings {
//   IPAMConfig: EndpointIpamConfig | undefined;
//   Links: string[] | undefined;
//   MacAddress: string | undefined;
//   Aliases: string[] | undefined;
//   DriverOpts: Map<string, string> | undefined;
//   NetworkID: string | undefined;
//   EndpointID: string | undefined;
//   Gateway: string | undefined;
//   IPAddress: string | undefined;
//   IPPrefixLen: number | undefined;
//   IPv6Gateway: string | undefined;
//   GlobalIPv6Address: string | undefined;
//   GlobalIPv6PrefixLen: number | undefined;
//   DNSNames: string[] | undefined;

//   constructor(obj?: {
//     IPAMConfig?: EndpointIpamConfig;
//     Links?: string[];
//     MacAddress?: string;
//     Aliases?: string[];
//     DriverOpts?: Record<string, string>;
//     NetworkID?: string;
//     EndpointID?: string;
//     Gateway?: string;
//     IPAddress?: string;
//     IPPrefixLen?: number;
//     IPv6Gateway?: string;
//     GlobalIPv6Address?: string;
//     GlobalIPv6PrefixLen?: number;
//     DNSNames?: string[];
//   }) {
//     this.IPAMConfig = obj?.IPAMConfig;
//     this.Links = obj?.Links;
//     this.MacAddress = obj?.MacAddress;
//     this.Aliases = obj?.Aliases;

//     if (obj?.DriverOpts) {
//       this.DriverOpts = new Map(Object.entries(obj.DriverOpts));
//     }

//     this.NetworkID = obj?.NetworkID;
//     this.EndpointID = obj?.EndpointID;
//     this.Gateway = obj?.Gateway;
//     this.IPAddress = obj?.IPAddress;
//     this.IPPrefixLen = obj?.IPPrefixLen;
//     this.IPv6Gateway = obj?.IPv6Gateway;
//     this.GlobalIPv6Address = obj?.GlobalIPv6Address;
//     this.GlobalIPv6PrefixLen = obj?.GlobalIPv6PrefixLen;
//     this.DNSNames = obj?.DNSNames;
//   }
// }

// export class NetworkingConfig {
//   EndpointsConfig: Map<string, EndpointSettings> | undefined;

//   constructor(obj?: { EndpointsConfig?: Record<string, EndpointSettings> }) {
//     if (obj?.EndpointsConfig) {
//       this.EndpointsConfig = new Map<string, EndpointSettings>(
//         Object.entries(obj.EndpointsConfig) as [string, EndpointSettings][]
//       );
//     }
//   }
// }

// export class DockerRunConfig {
//   Hostname: string | undefined;
//   Domainname: string | undefined;
//   User: string | undefined;
//   AttachStdin: boolean | undefined;
//   AttachStdout: boolean | undefined;
//   AttachStderr: boolean | undefined;
//   ExposedPorts: Map<string, Map<any, any>> | undefined;
//   Tty: boolean | undefined;
//   OpenStdin: boolean | undefined;
//   StdinOnce: boolean | undefined;
//   Env: string[] | undefined;
//   Cmd: string[] | undefined;
//   Healthcheck: HealthConfig | undefined;
//   ArgsEscaped: boolean | undefined;
//   Image: string | undefined;
//   Volumes: Map<string, Map<any, any>> | undefined;
//   WorkingDir: string | undefined;
//   Entrypoint: string[] | undefined;
//   NetworkDisabled: boolean | undefined;
//   MacAddress: string | undefined;
//   OnBuild: string[] | undefined;
//   Labels: Map<string, string> | undefined;
//   StopSignal: string | undefined;
//   StopTimeout: number | undefined;
//   Shell: string[] | undefined;
//   // HostConfig: HostConfig | undefined;
//   NetworkingConfig: NetworkingConfig | undefined;

//   constructor(obj?: {
//     Hostname?: string;
//     Domainname?: string;
//     User?: string;
//     AttachStdin?: boolean;
//     AttachStdout?: boolean;
//     AttachStderr?: boolean;
//     ExposedPorts?: Record<string, Record<any, any>>;
//     Tty?: boolean;
//     OpenStdin?: boolean;
//     StdinOnce?: boolean;
//     Env?: string[];
//     Cmd?: string[];
//     Healthcheck?: HealthConfig;
//     ArgsEscaped?: boolean;
//     Image?: string;
//     Volumes?: Record<string, Record<any, any>>;
//     WorkingDir?: string;
//     Entrypoint?: string[];
//     NetworkDisabled?: boolean;
//     MacAddress?: string;
//     OnBuild?: string[];
//     Labels?: Record<string, string>;
//     StopSignal?: string;
//     StopTimeout?: number;
//     Shell?: string[];
//     // HostConfig?: HostConfig;
//     NetworkingConfig?: NetworkingConfig;
//   }) {
//     this.Hostname = obj?.Hostname;
//     this.Domainname = obj?.Domainname;
//     this.User = obj?.User;
//     this.AttachStdin = obj?.AttachStdin;
//     this.AttachStdout = obj?.AttachStdout;
//     this.AttachStderr = obj?.AttachStderr;

//     if (obj?.ExposedPorts) {
//       this.ExposedPorts = new Map(
//         Object.entries(obj.ExposedPorts) as [string, Map<any, any>][]
//       );
//     }

//     this.Tty = obj?.Tty;
//     this.OpenStdin = obj?.OpenStdin;
//     this.StdinOnce = obj?.StdinOnce;
//     this.Env = obj?.Env;
//     this.Cmd = obj?.Cmd;
//     this.Healthcheck = obj?.Healthcheck;
//     this.ArgsEscaped = obj?.ArgsEscaped;
//     this.Image = obj?.Image;

//     if (obj?.Volumes) {
//       this.Volumes = new Map(
//         Object.entries(obj.Volumes) as [string, Map<any, any>][]
//       );
//     }

//     this.WorkingDir = obj?.WorkingDir;
//     this.Entrypoint = obj?.Entrypoint;
//     this.NetworkDisabled = obj?.NetworkDisabled;
//     this.MacAddress = obj?.MacAddress;
//     this.OnBuild = obj?.OnBuild;

//     if (obj?.Labels) {
//       this.Labels = new Map(Object.entries(obj.Labels) as [string, string][]);
//     }

//     this.StopSignal = obj?.StopSignal;
//     this.StopTimeout = obj?.StopTimeout;
//     this.Shell = obj?.Shell;
//     // this.HostConfig = obj?.HostConfig;
//     this.NetworkingConfig = obj?.NetworkingConfig;
//   }
// }

// export class EndpointIpamConfig {
//   IPv4Address: string | undefined;
//   IPv6Address: string | undefined;
//   LinkLocalIPs: string[] | undefined;

//   constructor(obj?: {
//     IPv4Address?: string;
//     IPv6Address?: string;
//     LinkLocalIPs?: string[];
//   }) {
//     this.IPv4Address = obj?.IPv4Address;
//     this.IPv6Address = obj?.IPv6Address;
//     this.LinkLocalIPs = obj?.LinkLocalIPs;
//   }
// }
