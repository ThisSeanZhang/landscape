import {
  getStaticNatMappingsV4,
  getStaticNatMappingV4,
  addStaticNatMappingV4,
  delStaticNatMappingV4,
  addManyStaticNatMappingsV4,
  checkStaticNatV4Conflict,
  getStaticNatMappingsV6,
  getStaticNatMappingV6,
  addStaticNatMappingV6,
  delStaticNatMappingV6,
  addManyStaticNatMappingsV6,
} from "@landscape-router/types/api/static-nat-mappings/static-nat-mappings";
import type {
  ApiStaticNatMappingV4Config as StaticNatMappingV4Config,
  ApiStaticNatMappingV6Config as StaticNatMappingV6Config,
  CheckStaticNatV4ConflictParams,
} from "@landscape-router/types/api/schemas";
import type { LandscapeApiRespPortConflictCheckResponseData } from "@landscape-router/types/api/schemas";

export type PortConflictCheckResponse =
  LandscapeApiRespPortConflictCheckResponseData;

// --- IPv4 ---

export async function get_static_nat_mappings_v4(): Promise<
  StaticNatMappingV4Config[]
> {
  return getStaticNatMappingsV4();
}

export async function get_static_nat_mapping_v4(
  id: string,
): Promise<StaticNatMappingV4Config> {
  return getStaticNatMappingV4(id);
}

export async function push_static_nat_mapping_v4(
  rule: StaticNatMappingV4Config,
): Promise<void> {
  await addStaticNatMappingV4(rule);
}

export async function push_many_static_nat_mapping_v4(
  rules: StaticNatMappingV4Config[],
): Promise<void> {
  await addManyStaticNatMappingsV4(rules);
}

export async function delete_static_nat_mapping_v4(id: string): Promise<void> {
  await delStaticNatMappingV4(id);
}

export async function check_static_nat_v4_conflict(
  wan_port: number,
  protocols: number[],
): Promise<LandscapeApiRespPortConflictCheckResponseData> {
  const params: CheckStaticNatV4ConflictParams = {
    wan_port,
    protocols: protocols.join(","),
  };
  return checkStaticNatV4Conflict(params);
}

// --- IPv6 ---

export async function get_static_nat_mappings_v6(): Promise<
  StaticNatMappingV6Config[]
> {
  return getStaticNatMappingsV6();
}

export async function get_static_nat_mapping_v6(
  id: string,
): Promise<StaticNatMappingV6Config> {
  return getStaticNatMappingV6(id);
}

export async function push_static_nat_mapping_v6(
  rule: StaticNatMappingV6Config,
): Promise<void> {
  await addStaticNatMappingV6(rule);
}

export async function push_many_static_nat_mapping_v6(
  rules: StaticNatMappingV6Config[],
): Promise<void> {
  await addManyStaticNatMappingsV6(rules);
}

export async function delete_static_nat_mapping_v6(id: string): Promise<void> {
  await delStaticNatMappingV6(id);
}
