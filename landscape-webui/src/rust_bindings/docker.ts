// This file was generated by [ts-rs](https://github.com/Aleph-Alpha/ts-rs). Do not edit this file manually.
import type { MacAddr } from "./network";

export type LandscapeDockerNetwork = { name: string, id: string, driver: string | null, containers: { [key in string]?: LandscapeDockerNetworkContainer }, iface_name: string, options: { [key in string]?: string }, };

export type LandscapeDockerNetworkContainer = { name: string, mac: MacAddr | null, };
