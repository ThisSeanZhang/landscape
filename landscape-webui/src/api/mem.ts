import type {
  GetMemoryModulesHistoryParams,
  GetMemoryPersistedHistoryParams,
  MemorySnapshot,
  MemorySeriesResponse,
  MemHistoryResponse,
} from "@landscape-router/types/api/schemas";
import {
  getMemoryModules as _getMemoryModules,
  getMemoryModulesHistory as _getMemoryModulesHistory,
  getMemoryPersistedHistory as _getMemoryPersistedHistory,
} from "@landscape-router/types/api/memory/memory";

export type {
  GetMemoryModulesHistoryParams,
  GetMemoryPersistedHistoryParams,
  MemorySnapshot,
  MemorySeriesResponse,
  MemHistoryResponse,
};

export async function get_memory_modules(): Promise<MemorySnapshot> {
  return _getMemoryModules({ silent: true });
}

export async function get_memory_modules_history(
  params?: GetMemoryModulesHistoryParams,
): Promise<MemorySeriesResponse> {
  return _getMemoryModulesHistory(params, { silent: true });
}

export async function get_memory_history(
  params: GetMemoryPersistedHistoryParams,
): Promise<MemHistoryResponse> {
  return _getMemoryPersistedHistory(params, { silent: true });
}
