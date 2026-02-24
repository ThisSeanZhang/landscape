<script setup lang="ts">
import { ref } from "vue";
import { do_login } from "@/api/auth";
import type { LoginInfo } from "landscape-types/api/schemas";
import { useRouter, useRoute } from "vue-router";
import { useMessage } from "naive-ui";

import CopyRight from "@/components/CopyRight.vue";
import { LANDSCAPE_TOKEN_KEY } from "@/lib/common";
import { useFrontEndStore } from "@/stores/front_end_config";

const login_info = ref<LoginInfo>({ username: "", password: "" });

const router = useRouter();
const route = useRoute();
const frontEndStore = useFrontEndStore();
const message = useMessage();

async function login() {
  localStorage.removeItem(LANDSCAPE_TOKEN_KEY);
  let result = await do_login(login_info.value);
  if (result.success) {
    localStorage.setItem(LANDSCAPE_TOKEN_KEY, result.token);
  }
  frontEndStore.INSERT_USERNAME(login_info.value.username);
  let redirect = (history.state?.redirect as string) || "/";
  if (redirect === "/login") {
    redirect = "/";
  }
  router.push({
    path: redirect,
  });
  message.success(`欢迎, ${login_info.value.username}`);
}
</script>

<template>
  <n-layout position="absolute" style="height: 100%" content-style=" ">
    <n-layout-header style="height: 24px; padding: 0 10px; display: flex">
      <n-flex style="flex: 1" justify="space-between" align="center">
        <n-flex>Landscape</n-flex>
        <n-flex>
          <LanguageSetting />
        </n-flex>
      </n-flex>
    </n-layout-header>

    <n-layout-content
      position="absolute"
      style="top: 24px; bottom: 24px"
      content-style="display: flex"
    >
      <n-flex style="flex: 1" align="center" justify="center">
        <n-card title="登录" style="max-width: 400px">
          <n-form>
            <n-form-item-row label="用户名">
              <n-input v-model:value="login_info.username" />
            </n-form-item-row>
            <n-form-item-row label="密码">
              <n-input
                type="password"
                show-password-on="click"
                @keyup.enter="login()"
                v-model:value="login_info.password"
              />
            </n-form-item-row>
          </n-form>
          <n-button type="primary" block secondary strong @click="login">
            登录
          </n-button>
        </n-card>
      </n-flex>
    </n-layout-content>
    <n-layout-footer position="absolute" style="height: 24px">
      <CopyRight></CopyRight>
    </n-layout-footer>
  </n-layout>
</template>
