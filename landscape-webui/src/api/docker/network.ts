import api from "@/api";
import { LandscapeDockerNetwork } from "@/lib/docker/network";

export async function get_all_docker_networks(): Promise<LandscapeDockerNetwork[]> {
  let data = await api.api.get("docker/networks");
  return data.data.map((d: any) => new LandscapeDockerNetwork(d));
}
