import type { LandscapeDockerNetwork } from "@landscape-router/types/api/schemas";
import { getAllDockerNetworks } from "@landscape-router/types/api/docker-networks/docker-networks";

export async function get_all_docker_networks(): Promise<
  LandscapeDockerNetwork[]
> {
  return getAllDockerNetworks();
}
