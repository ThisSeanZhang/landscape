import { ServiceStatus } from "@/lib/services";
import { DockerContainerSummary, DockerImageSummary } from "@/lib/docker";
import {
  DockerCmd,
  GetDockerPullTasks200DataItem as PullImgTask,
} from "landscape-types/api/schemas";
import {
  getDockerStatus as _getDockerStatus,
  startDockerStatus as _startDockerStatus,
  stopDockerStatus as _stopDockerStatus,
  getAllContainers,
  startContainer as _startContainer,
  stopContainer as _stopContainer,
  removeContainer as _removeContainer,
  runCmdContainer as _runCmdContainer,
} from "landscape-types/api/docker/docker";
import {
  getAllDockerImages,
  pullDockerImage as _pullDockerImage,
  getDockerPullTasks,
  deleteDockerImage as _deleteDockerImage,
} from "landscape-types/api/docker-images/docker-images";

export type { PullImgTask };

export async function get_docker_status(): Promise<ServiceStatus> {
  return _getDockerStatus();
}

export async function start_docker_service(): Promise<ServiceStatus> {
  return _startDockerStatus();
}

export async function stop_docker_service(): Promise<ServiceStatus> {
  return _stopDockerStatus();
}

export async function get_docker_container_summarys(): Promise<
  DockerContainerSummary[]
> {
  const data: any[] = (await getAllContainers()) as any;
  return data.map((d: any) => new DockerContainerSummary(d));
}

export async function start_container(name: string): Promise<void> {
  await _startContainer(name);
}

export async function stop_container(name: string): Promise<void> {
  await _stopContainer(name);
}

export async function remove_container(name: string): Promise<void> {
  await _removeContainer(name);
}

export async function run_cmd(docker_cmd: DockerCmd): Promise<void> {
  await _runCmdContainer(docker_cmd);
}

export async function get_docker_images(): Promise<DockerImageSummary[]> {
  const data: any[] = (await getAllDockerImages()) as any;
  return data.map((d: any) => new DockerImageSummary(d));
}

export async function pull_docker_image(image_name: string): Promise<void> {
  await _pullDockerImage({ image_name, tag: null });
}

export async function get_current_tasks(): Promise<PullImgTask[]> {
  return getDockerPullTasks();
}

export async function delete_docker_image(id: string): Promise<void> {
  await _deleteDockerImage(id);
}
