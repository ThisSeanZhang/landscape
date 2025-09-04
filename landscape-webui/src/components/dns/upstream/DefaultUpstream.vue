<script setup lang="ts">
import { DnsUpstreamConfig } from "@/rust_bindings/common/dns";
import { DnsUpstreamModeTsEnum } from "@/lib/dns";

const rule = defineModel<DnsUpstreamConfig>("rule", { required: true });

enum DefaultDnsConfig {
  ALI_UDP = "ali-udp",
  ALI_DOH = "ali-doh",
  ALI_DOT = "ali-dot",

  DNSPOD_UDP = "dnspod-udp",
  DNSPOD_DOH = "dnspod-doh",
  DNSPOD_DOT = "dnspod-dot",

  CLOUDFLARE_UDP = "cloudflare-udp",
  CLOUDFLARE_DOH = "cloudflare-doh",
  CLOUDFLARE_DOT = "cloudflare-dot",
  CLOUDFLARE_DOQ = "cloudflare-doq",

  GOOGLE_UDP = "google-udp",
  GOOGLE_DOH = "google-doh",
  GOOGLE_DOT = "google-dot",
  GOOGLE_DOQ = "google-doq",
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
  },
  [DefaultDnsConfig.ALI_DOH]: {
    mode: { t: DnsUpstreamModeTsEnum.Https, domain: "dns.alidns.com" },
    ips: ["223.5.5.5", "223.6.6.6", "2400:3200::1", "2400:3200:baba::1"],
    port: 443,
  },
  [DefaultDnsConfig.ALI_DOT]: {
    mode: { t: DnsUpstreamModeTsEnum.Tls, domain: "dns.alidns.com" },
    ips: ["223.5.5.5", "223.6.6.6", "2400:3200::1", "2400:3200:baba::1"],
    port: 853,
  },

  // DNSPod
  [DefaultDnsConfig.DNSPOD_UDP]: {
    mode: { t: DnsUpstreamModeTsEnum.Plaintext },
    ips: ["1.12.12.12", "120.53.53.53"],
    port: 53,
  },
  [DefaultDnsConfig.DNSPOD_DOH]: {
    mode: { t: DnsUpstreamModeTsEnum.Https, domain: "dns.pub" },
    ips: ["1.12.12.12", "120.53.53.53"],
    port: 443,
  },
  [DefaultDnsConfig.DNSPOD_DOT]: {
    mode: { t: DnsUpstreamModeTsEnum.Tls, domain: "dot.pub" },
    ips: ["1.12.12.12", "120.53.53.53"],
    port: 853,
  },

  // Cloudflare
  [DefaultDnsConfig.CLOUDFLARE_UDP]: {
    mode: { t: DnsUpstreamModeTsEnum.Plaintext },
    ips: ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"],
    port: 53,
  },
  [DefaultDnsConfig.CLOUDFLARE_DOH]: {
    mode: { t: DnsUpstreamModeTsEnum.Https, domain: "cloudflare-dns.com" },
    ips: ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"],
    port: 443,
  },
  [DefaultDnsConfig.CLOUDFLARE_DOT]: {
    mode: { t: DnsUpstreamModeTsEnum.Tls, domain: "cloudflare-dns.com" },
    ips: ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"],
    port: 853,
  },
  [DefaultDnsConfig.CLOUDFLARE_DOQ]: {
    mode: { t: DnsUpstreamModeTsEnum.Quic, domain: "cloudflare-dns.com" },
    ips: ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"],
    port: 784,
  },

  // Google
  [DefaultDnsConfig.GOOGLE_UDP]: {
    mode: { t: DnsUpstreamModeTsEnum.Plaintext },
    ips: ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"],
    port: 53,
  },
  [DefaultDnsConfig.GOOGLE_DOH]: {
    mode: { t: DnsUpstreamModeTsEnum.Https, domain: "dns.google" },
    ips: ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"],
    port: 443,
  },
  [DefaultDnsConfig.GOOGLE_DOT]: {
    mode: { t: DnsUpstreamModeTsEnum.Tls, domain: "dns.google" },
    ips: ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"],
    port: 853,
  },
  [DefaultDnsConfig.GOOGLE_DOQ]: {
    mode: { t: DnsUpstreamModeTsEnum.Quic, domain: "dns.google" },
    ips: ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"],
    port: 784,
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
  <n-flex align="center" justify="space-between">
    <n-flex>
      <n-input-group>
        <n-input-group-label :size="btn_size" class="label-len">
          阿里
        </n-input-group-label>
        <n-button
          @click="replace_default(DefaultDnsConfig.ALI_UDP)"
          :size="btn_size"
          secondary
          strong
        >
          UDP
        </n-button>
        <n-button
          @click="replace_default(DefaultDnsConfig.ALI_DOH)"
          :size="btn_size"
          secondary
          strong
        >
          DoH
        </n-button>
        <n-button
          @click="replace_default(DefaultDnsConfig.ALI_DOT)"
          :size="btn_size"
          secondary
          strong
        >
          DoT
        </n-button>
      </n-input-group>
    </n-flex>

    <n-flex>
      <n-input-group>
        <n-input-group-label :size="btn_size" class="label-len">
          Cloudflare
        </n-input-group-label>
        <n-button
          @click="replace_default(DefaultDnsConfig.CLOUDFLARE_UDP)"
          :size="btn_size"
          secondary
          strong
        >
          UDP
        </n-button>
        <n-button
          @click="replace_default(DefaultDnsConfig.CLOUDFLARE_DOH)"
          :size="btn_size"
          secondary
          strong
        >
          DoH
        </n-button>
        <n-button
          @click="replace_default(DefaultDnsConfig.CLOUDFLARE_DOT)"
          :size="btn_size"
          secondary
          strong
        >
          DoT
        </n-button>
        <n-button
          @click="replace_default(DefaultDnsConfig.CLOUDFLARE_DOQ)"
          :size="btn_size"
          secondary
          strong
        >
          DoQ
        </n-button>
      </n-input-group>
    </n-flex>

    <n-flex>
      <n-input-group>
        <n-input-group-label :size="btn_size" class="label-len">
          DNSPod
        </n-input-group-label>
        <n-button
          @click="replace_default(DefaultDnsConfig.DNSPOD_UDP)"
          :size="btn_size"
          secondary
          strong
        >
          UDP
        </n-button>
        <n-button
          @click="replace_default(DefaultDnsConfig.DNSPOD_DOH)"
          :size="btn_size"
          secondary
          strong
        >
          DoH
        </n-button>
        <n-button
          @click="replace_default(DefaultDnsConfig.DNSPOD_DOT)"
          :size="btn_size"
          secondary
          strong
        >
          DoT
        </n-button>
      </n-input-group>
    </n-flex>

    <n-flex>
      <n-input-group>
        <n-input-group-label :size="btn_size" class="label-len">
          Google
        </n-input-group-label>
        <n-button
          @click="replace_default(DefaultDnsConfig.GOOGLE_UDP)"
          :size="btn_size"
          secondary
          strong
        >
          UDP
        </n-button>
        <n-button
          @click="replace_default(DefaultDnsConfig.GOOGLE_DOH)"
          :size="btn_size"
          secondary
          strong
        >
          DoH
        </n-button>
        <n-button
          @click="replace_default(DefaultDnsConfig.GOOGLE_DOT)"
          :size="btn_size"
          secondary
          strong
        >
          DoT
        </n-button>
        <n-button
          @click="replace_default(DefaultDnsConfig.GOOGLE_DOQ)"
          :size="btn_size"
          secondary
          strong
        >
          DoQ
        </n-button>
      </n-input-group>
    </n-flex>
  </n-flex>
</template>
<style scope>
.label-len {
  width: 90px;
  text-align: center;
}
</style>
