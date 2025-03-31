export class LandscapeDockerNetwork {
  name: string;
  iface_name: string;
  id: string;
  driver?: string;
  containers: Map<string, LandscapeDockerNetworkContainer>;
  options: Map<string, string>;

  constructor(obj: {
    name: string;
    iface_name: string;
    id: string;
    driver?: string;
    containers: Map<string, LandscapeDockerNetworkContainer>;
    options: Map<string, string>;
  }) {
    this.name = obj.name;
    this.iface_name = obj.iface_name;
    this.id = obj.id;
    this.driver = obj.driver;

    let map = new Map<string, LandscapeDockerNetworkContainer>();
    for (const [key, value] of Object.entries(obj?.containers)) {
      map.set(key, new LandscapeDockerNetworkContainer(value));
    }
    this.containers = map;

    let options = new Map<string, string>();
    for (const [key, value] of Object.entries(obj?.containers)) {
      options.set(key, value as string);
    }
    this.options = options;
  }
}

export class LandscapeDockerNetworkContainer {
  name: string;
  mac: string | undefined;
  constructor(obj: { name: string; mac?: string }) {
    this.name = obj.name;
    this.mac = obj.mac;
  }
}
