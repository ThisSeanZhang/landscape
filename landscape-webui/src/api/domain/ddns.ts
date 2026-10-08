import {
  createDdnsJob,
  deleteDdnsJob,
  getDdnsJob,
  listDdnsJobs,
  listDdnsJobStatus,
  triggerDdnsJobSync,
  updateDdnsJob,
} from "@landscape-router/types/api/ddns/ddns";
import type {
  ApiDdnsJob as DdnsJob,
  DdnsJobRuntime,
} from "@landscape-router/types/api/schemas";

export async function get_ddns_jobs(): Promise<DdnsJob[]> {
  return listDdnsJobs();
}

export async function get_ddns_job_status(): Promise<DdnsJobRuntime[]> {
  return listDdnsJobStatus();
}

export async function get_ddns_job(id: string) {
  return getDdnsJob(id);
}

export async function push_ddns_job(payload: DdnsJob) {
  if (payload.id) {
    return updateDdnsJob(payload.id, payload);
  }
  return createDdnsJob(payload);
}

export async function delete_ddns_job(id: string): Promise<void> {
  await deleteDdnsJob(id);
}

export async function sync_ddns_job(id: string): Promise<DdnsJobRuntime> {
  return triggerDdnsJobSync(id);
}
