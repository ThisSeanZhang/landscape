import { useThemeVars } from "naive-ui";

export const LAND_REDIRECT_ID_KEY = "ld_flow_edge";

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
  Id: string;
  Created: number | undefined;
  Labels: Map<string, string> | undefined;
  RepoTags: string[] | undefined;
  Size: number | undefined;
  constructor(obj?: {
    Id: string;
    Created?: number;
    Labels?: any | undefined;
    RepoTags: string[];
    Size: number | undefined;
  }) {
    this.Id = obj?.Id ?? "";
    this.Created = obj?.Created;
    this.RepoTags = obj?.RepoTags;
    this.Size = obj?.Size;
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
