import { LandscapeDockerNetwork } from "@/lib/docker/network";
import { getAllDockerNetworks } from "landscape-types/api/docker-networks/docker-networks";

export async function get_all_docker_networks(): Promise<
  LandscapeDockerNetwork[]
> {
  const data = await getAllDockerNetworks();
  return data.map((d: any) => new LandscapeDockerNetwork(d));
}
