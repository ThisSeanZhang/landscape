import {
  listCertAccounts,
  getCertAccount,
  createCertAccount,
  deleteCertAccount,
  registerCertAccount,
  verifyCertAccount,
  deactivateCertAccount,
} from "@landscape-router/types/api/certificate-accounts/certificate-accounts";
import type { CertAccountConfig } from "@landscape-router/types/api/schemas";

export async function get_cert_accounts(): Promise<CertAccountConfig[]> {
  return listCertAccounts();
}

export async function get_cert_account(id: string): Promise<CertAccountConfig> {
  return getCertAccount(id);
}

export async function push_cert_account(
  config: CertAccountConfig,
): Promise<CertAccountConfig> {
  return createCertAccount(config);
}

export async function delete_cert_account(id: string): Promise<void> {
  await deleteCertAccount(id);
}

export async function register_cert_account(
  id: string,
): Promise<CertAccountConfig> {
  return registerCertAccount(id);
}

export async function verify_cert_account(
  id: string,
): Promise<CertAccountConfig> {
  return verifyCertAccount(id);
}

export async function deactivate_cert_account_api(
  id: string,
): Promise<CertAccountConfig> {
  return deactivateCertAccount(id);
}
