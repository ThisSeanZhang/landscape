import { ServiceStatus } from "@/lib/services";
import {
  DockerCmd,
  DockerContainerSummary,
  DockerImageSummary,
} from "@/lib/docker";
import axiosService from "@/api";

export async function get_docker_status(): Promise<ServiceStatus> {
  let data = await axiosService.get("docker/status");
  //   console.log(data.data);
  return new ServiceStatus(data.data);
}

export async function start_docker_service(): Promise<ServiceStatus> {
  let data = await axiosService.post("docker/status");
  //   console.log(data.data);
  return new ServiceStatus(data.data);
}
export async function stop_docker_service(): Promise<ServiceStatus> {
  let data = await axiosService.delete("docker/status");
  //   console.log(data.data);
  return new ServiceStatus(data.data);
}

export async function get_docker_container_summarys(): Promise<
  DockerContainerSummary[]
> {
  let data = await axiosService.get("docker/container_summarys");
  // console.log(data.data);
  return data.data.map((d: any) => new DockerContainerSummary(d));
}

export async function start_container(name: string): Promise<any> {
  let data = await axiosService.post(`docker/start/${name}`);
  console.log(data.data);
  return;
}

export async function stop_container(name: string): Promise<any> {
  let data = await axiosService.post(`docker/stop/${name}`, undefined, {
    timeout: 60000,
  });
  console.log(data.data);
  return;
}

export async function remove_container(name: string): Promise<any> {
  let data = await axiosService.post(`docker/remove/${name}`);
  console.log(data.data);
  return;
}

export async function run_cmd(docker_cmd: DockerCmd): Promise<any> {
  let data = await axiosService.post(`docker/run_cmd`, docker_cmd);
  console.log(data.data);
  return;
}

export async function get_docker_images(): Promise<DockerImageSummary[]> {
  let data = await axiosService.get("docker/images");
  // console.log(data.data);
  return data.data.map((d: any) => new DockerImageSummary(d));
}

export async function pull_docker_image(name: string): Promise<any> {
  let data = await axiosService.post(`docker/images/${name}`);
  // console.log(data.data);
  return data.data.map((d: any) => new DockerImageSummary(d));
}

export async function delete_docker_image(id: string): Promise<void> {
  let data = await axiosService.delete(`docker/images/id/${id}`);
  // console.log(data.data);
  return;
}
