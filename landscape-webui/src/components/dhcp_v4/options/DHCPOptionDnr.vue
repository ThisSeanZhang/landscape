<script setup lang="ts">
import type { DhcpV4DnrOptionConfig } from "./types";

const model = defineModel<DhcpV4DnrOptionConfig>({ required: true });

const modeOptions = [
  { label: "使用本机 DoH", value: "local" },
  { label: "自定义 DoH", value: "custom" },
];

function updateMode(mode: "local" | "custom") {
  if (mode === "local") {
    model.value = { mode: "local" };
  } else {
    model.value = {
      mode: "custom",
      domains: [],
      ips: [],
      port: null,
      doh_path: null,
    };
  }
}
</script>

<template>
  <n-space vertical size="small">
    <n-select
      :value="model.mode"
      :options="modeOptions"
      style="max-width: 240px"
      @update:value="updateMode"
    />
    <n-alert v-if="model.mode === 'local'" type="info" :bordered="false">
      自动使用本机 API/DoH 证书域名、当前 DHCP 服务地址、DoH 端口和 DoH 路径生成
      DHCP Option 162。
    </n-alert>
    <template v-else>
      <n-alert type="info" :bordered="false">
        未填写的字段会回退到本机 DoH
        配置；域名必须填写证书实际覆盖的精确主机名，不会自动把通配符域名转换为裸域名。
      </n-alert>
      <n-form-item label="DoH 域名">
        <n-dynamic-tags v-model:value="model.domains" />
      </n-form-item>
      <n-form-item label="IPv4 地址">
        <n-dynamic-tags v-model:value="model.ips" />
      </n-form-item>
      <n-form-item label="端口">
        <n-input-number
          v-model:value="model.port"
          :min="1"
          :max="65535"
          placeholder="默认使用本机 DoH 端口"
          style="width: 100%"
        />
      </n-form-item>
      <n-form-item label="DoH 路径">
        <n-input
          v-model:value="model.doh_path"
          placeholder="默认使用本机 DoH 路径，例如 /dns-query"
          style="width: 100%"
        />
      </n-form-item>
    </template>
  </n-space>
</template>
