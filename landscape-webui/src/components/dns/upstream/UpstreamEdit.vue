<script setup lang="ts">
import {
  DnsUpstreamMode,
  get_dns_upstream_type_options,
  DNSResolveModeEnum,
  DnsUpstreamTypeEnum,
} from "@/lib/dns";

const upstream_mode = defineModel<DnsUpstreamMode>("value", { required: true });

function onCreate(): string {
  return "";
}
function update_upstream(t: DnsUpstreamTypeEnum) {
  switch (t) {
    case DnsUpstreamTypeEnum.Plaintext: {
      upstream_mode.value.port = 53;
      break;
    }
    case DnsUpstreamTypeEnum.Https: {
      upstream_mode.value.port = 443;
      break;
    }
    case DnsUpstreamTypeEnum.Tls: {
      upstream_mode.value.port = 853;
      break;
    }
  }
}
</script>
<template>
  <n-grid :cols="5">
    <n-form-item-gi :span="3" label="连接方式">
      <!-- {{ upstream_mode }} -->
      <n-radio-group
        v-model:value="upstream_mode.upstream.t"
        name="upstream_flag"
        @update:value="update_upstream"
      >
        <n-radio-button
          v-for="opt in get_dns_upstream_type_options()"
          :key="opt.value"
          :value="opt.value"
          :label="opt.label"
        />
      </n-radio-group>
    </n-form-item-gi>
    <n-form-item-gi :span="2" label="端口">
      <n-input-number
        v-model:value="upstream_mode.port"
        min="1"
        max="35565"
        placeholder=""
      />
    </n-form-item-gi>
    <n-form-item-gi
      v-if="upstream_mode.upstream.t !== DnsUpstreamTypeEnum.Plaintext"
      :span="5"
      label="域名"
    >
      <n-input
        v-model:value="upstream_mode.upstream.domain"
        placeholder="上游 DNS 域名"
      />
    </n-form-item-gi>
    <n-form-item-gi :span="5" label="上游 IP ">
      <n-dynamic-input v-model:value="upstream_mode.ips" :on-create="onCreate">
        <template #create-button-default> 增加一条上游服务器 IP 信息 </template>
      </n-dynamic-input>
    </n-form-item-gi>
  </n-grid>
</template>
