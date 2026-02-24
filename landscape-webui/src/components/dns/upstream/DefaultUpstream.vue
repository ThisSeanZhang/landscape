<script setup lang="ts">
import type { DnsUpstreamConfig } from "@landscape-router/types/api/schemas";
import { DnsUpstreamModeTsEnum } from "@/lib/dns";

const rule = defineModel<DnsUpstreamConfig>("rule", { required: true });

enum DefaultDnsConfig {
  ALI_UDP = "ali-udp",
  ALI_DOH = "ali-doh",
  ALI_DOT = "ali-dot",
  ALI_DOQ = "ali-doq",

  DNSPOD_UDP = "dnspod-udp",
  DNSPOD_DOH = "dnspod-doh",
  // DNSPOD_DOT = "dnspod-dot",

  CLOUDFLARE_UDP = "cloudflare-udp",
  CLOUDFLARE_DOH = "cloudflare-doh",
  CLOUDFLARE_DOT = "cloudflare-dot",

  GOOGLE_UDP = "google-udp",
  GOOGLE_DOH = "google-doh",
  GOOGLE_DOT = "google-dot",
}

const DEFAULT_CONFIGS: Record<
  DefaultDnsConfig,
  Omit<DnsUpstreamConfig, "id" | "remark">
> = {
  // 阿里
  [DefaultDnsConfig.ALI_UDP]: {
    mode: { t: DnsUpstreamModeTsEnum.Plaintext },
    ips: ["223.5.5.5", "223.6.6.6", "2400:3200::1", "2400:3200:baba::1"],
    port: 53,
    enable_ip_validation: false,
  },
  [DefaultDnsConfig.ALI_DOH]: {
    mode: {
      t: DnsUpstreamModeTsEnum.Https,
      domain: "dns.alidns.com",
      http_endpoint: null,
    },
    ips: ["223.5.5.5", "223.6.6.6", "2400:3200::1", "2400:3200:baba::1"],
    port: 443,
    enable_ip_validation: false,
  },
  [DefaultDnsConfig.ALI_DOT]: {
    mode: { t: DnsUpstreamModeTsEnum.Tls, domain: "dns.alidns.com" },
    ips: ["223.5.5.5", "223.6.6.6", "2400:3200::1", "2400:3200:baba::1"],
    port: 853,
    enable_ip_validation: false,
  },
  [DefaultDnsConfig.ALI_DOQ]: {
    mode: { t: DnsUpstreamModeTsEnum.Quic, domain: "dns.alidns.com" },
    ips: ["223.5.5.5", "223.6.6.6", "2400:3200::1", "2400:3200:baba::1"],
    port: 853,
    enable_ip_validation: false,
  },

  // DNSPod
  [DefaultDnsConfig.DNSPOD_UDP]: {
    mode: { t: DnsUpstreamModeTsEnum.Plaintext },
    ips: [
      "119.29.29.29",
      "119.28.28.28",
      "240c::6666",
      "240c::6644",
      "182.254.116.116",
      "2402:4e00::",
    ],
    port: 53,
    enable_ip_validation: false,
  },
  [DefaultDnsConfig.DNSPOD_DOH]: {
    mode: {
      t: DnsUpstreamModeTsEnum.Https,
      domain: "dns.pub",
      http_endpoint: null,
    },
    ips: ["1.12.12.21", "120.53.53.53"],
    port: 443,
    enable_ip_validation: false,
  },
  // [DefaultDnsConfig.DNSPOD_DOT]: {
  //   mode: { t: DnsUpstreamModeTsEnum.Tls, domain: "dot.pub" },
  //   ips: ["1.12.12.21", "120.53.53.53"],
  //   port: 853,
  //   enable_ip_validation: false,
  // },

  // Cloudflare
  [DefaultDnsConfig.CLOUDFLARE_UDP]: {
    mode: { t: DnsUpstreamModeTsEnum.Plaintext },
    ips: ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"],
    port: 53,
    enable_ip_validation: false,
  },
  [DefaultDnsConfig.CLOUDFLARE_DOH]: {
    mode: {
      t: DnsUpstreamModeTsEnum.Https,
      domain: "cloudflare-dns.com",
      http_endpoint: null,
    },
    ips: ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"],
    port: 443,
    enable_ip_validation: false,
  },
  [DefaultDnsConfig.CLOUDFLARE_DOT]: {
    mode: { t: DnsUpstreamModeTsEnum.Tls, domain: "cloudflare-dns.com" },
    ips: ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"],
    port: 853,
    enable_ip_validation: false,
  },

  // Google
  [DefaultDnsConfig.GOOGLE_UDP]: {
    mode: { t: DnsUpstreamModeTsEnum.Plaintext },
    ips: ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"],
    port: 53,
    enable_ip_validation: false,
  },
  [DefaultDnsConfig.GOOGLE_DOH]: {
    mode: {
      t: DnsUpstreamModeTsEnum.Https,
      domain: "dns.google",
      http_endpoint: null,
    },
    ips: ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"],
    port: 443,
    enable_ip_validation: false,
  },
  [DefaultDnsConfig.GOOGLE_DOT]: {
    mode: { t: DnsUpstreamModeTsEnum.Tls, domain: "dns.google" },
    ips: ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"],
    port: 853,
    enable_ip_validation: false,
  },
};

function replace_default(config: DefaultDnsConfig) {
  rule.value = {
    id: rule.value.id,
    remark: rule.value?.remark ?? "",
    ...DEFAULT_CONFIGS[config],
  };
}

const btn_size = "small";
</script>
<template>
  <n-flex justify="space-between" :size="[12, 8]">
    <n-flex vertical :size="8">
      <n-input-group>
        <n-input-group-label :size="btn_size" class="label-len">
          阿里
        </n-input-group-label>
        <n-button
          @click="replace_default(DefaultDnsConfig.ALI_UDP)"
          :size="btn_size"
          secondary
          strong
          >UDP</n-button
        >
        <n-button
          @click="replace_default(DefaultDnsConfig.ALI_DOH)"
          :size="btn_size"
          secondary
          strong
          >DoH</n-button
        >
        <n-button
          @click="replace_default(DefaultDnsConfig.ALI_DOT)"
          :size="btn_size"
          secondary
          strong
          >DoT</n-button
        >
        <n-button
          @click="replace_default(DefaultDnsConfig.ALI_DOQ)"
          :size="btn_size"
          secondary
          strong
          >DoQ</n-button
        >
      </n-input-group>
      <n-input-group>
        <n-input-group-label :size="btn_size" class="label-len">
          DNSPod
        </n-input-group-label>
        <n-button
          @click="replace_default(DefaultDnsConfig.DNSPOD_UDP)"
          :size="btn_size"
          secondary
          strong
          >UDP</n-button
        >
        <n-button
          @click="replace_default(DefaultDnsConfig.DNSPOD_DOH)"
          :size="btn_size"
          secondary
          strong
          >DoH</n-button
        >
        <!-- <n-button
          @click="replace_default(DefaultDnsConfig.DNSPOD_DOT)"
          :size="btn_size"
          secondary
          strong
          >DoT</n-button
        > -->
      </n-input-group>
    </n-flex>
    <n-flex vertical :size="8">
      <n-input-group>
        <n-input-group-label :size="btn_size" class="label-len">
          Cloudflare
        </n-input-group-label>
        <n-button
          @click="replace_default(DefaultDnsConfig.CLOUDFLARE_UDP)"
          :size="btn_size"
          secondary
          strong
          >UDP</n-button
        >
        <n-button
          @click="replace_default(DefaultDnsConfig.CLOUDFLARE_DOH)"
          :size="btn_size"
          secondary
          strong
          >DoH</n-button
        >
        <n-button
          @click="replace_default(DefaultDnsConfig.CLOUDFLARE_DOT)"
          :size="btn_size"
          secondary
          strong
          >DoT</n-button
        >
      </n-input-group>
      <n-input-group>
        <n-input-group-label :size="btn_size" class="label-len">
          Google
        </n-input-group-label>
        <n-button
          @click="replace_default(DefaultDnsConfig.GOOGLE_UDP)"
          :size="btn_size"
          secondary
          strong
          >UDP</n-button
        >
        <n-button
          @click="replace_default(DefaultDnsConfig.GOOGLE_DOH)"
          :size="btn_size"
          secondary
          strong
          >DoH</n-button
        >
        <n-button
          @click="replace_default(DefaultDnsConfig.GOOGLE_DOT)"
          :size="btn_size"
          secondary
          strong
          >DoT</n-button
        >
      </n-input-group>
    </n-flex>
  </n-flex>
</template>
<style scoped>
.label-len {
  width: 90px;
  text-align: center;
}
</style>
