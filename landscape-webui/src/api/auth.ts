import type { LoginInfo } from "@landscape-router/types/api/schemas";
import { loginHandler } from "@landscape-router/types/api/auth/auth";

export async function do_login(login: LoginInfo) {
  return loginHandler(login);
}
