import {
  getStaticNatMappings,
  getStaticNatMapping,
  addStaticNatMappings,
  delStaticNatMappings,
  addManyStaticNatMappings,
} from "@landscape-router/types/api/static-nat-mappings/static-nat-mappings";
import type { StaticNatMappingConfig } from "@landscape-router/types/api/schemas";

export async function get_static_nat_mappings(): Promise<
  StaticNatMappingConfig[]
> {
  return getStaticNatMappings();
}

export async function get_static_nat_mapping(
  id: string,
): Promise<StaticNatMappingConfig> {
  return getStaticNatMapping(id);
}

export async function push_static_nat_mapping(
  rule: StaticNatMappingConfig,
): Promise<void> {
  await addStaticNatMappings(rule);
}

export async function delete_static_nat_mapping(id: string): Promise<void> {
  await delStaticNatMappings(id);
}

export async function push_many_static_nat_mapping(
  rule: StaticNatMappingConfig[],
): Promise<void> {
  await addManyStaticNatMappings(rule);
}
