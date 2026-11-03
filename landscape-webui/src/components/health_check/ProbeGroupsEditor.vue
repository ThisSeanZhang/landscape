<script setup lang="ts">
import type {
  WanProbeGroup,
  WanProbeTarget,
} from "@landscape-router/types/api/schemas";
import { useI18n } from "vue-i18n";
const groups = defineModel<WanProbeGroup[]>({ required: true });
const { t } = useI18n();
function target(kind: "icmp" | "dns" | "http", v6 = false): WanProbeTarget {
  const ip = v6 ? "2400:3200::1" : "223.5.5.5";
  if (kind === "dns") return { t: kind, server: ip, domain: "www.baidu.com" };
  if (kind === "http")
    return { t: kind, dns_server: ip, url: "https://www.baidu.com" };
  return { t: "icmp", address: ip };
}
function addTarget(group: WanProbeGroup) {
  const first = group.targets[0];
  const ip =
    first.t === "icmp"
      ? first.address
      : first.t === "dns"
        ? first.server
        : first.dns_server;
  group.targets.push(target("icmp", ip.includes(":")));
}
function changeKind(
  group: WanProbeGroup,
  index: number,
  kind: "icmp" | "dns" | "http",
) {
  const old = group.targets[index];
  const ip =
    old.t === "icmp"
      ? old.address
      : old.t === "dns"
        ? old.server
        : old.dns_server;
  group.targets[index] = target(kind, ip.includes(":"));
}
</script>
<template>
  <n-alert type="info" :show-icon="false" style="margin-bottom: 12px">{{
    t("network.health_check.multi_hint")
  }}</n-alert>
  <n-card
    v-for="(group, index) in groups"
    :key="index"
    size="small"
    style="margin-bottom: 12px"
  >
    <n-flex align="center" :wrap="false">
      <n-input
        v-model:value="group.name"
        :placeholder="t('network.health_check.group_name')"
      />
      <n-button
        size="small"
        :disabled="groups.length <= 1"
        @click="groups.splice(index, 1)"
        >{{ t("common.delete") }}</n-button
      >
    </n-flex>
    <n-form-item
      :label="t('network.health_check.quorum')"
      style="margin-top: 10px"
    >
      <n-input-number
        v-model:value="group.quorum"
        :min="1"
        :max="group.targets.length"
      />
    </n-form-item>
    <n-card
      v-for="(probe, i) in group.targets"
      :key="i"
      size="small"
      style="margin-bottom: 8px"
    >
      <n-flex :wrap="false" style="margin-bottom: 8px">
        <n-select
          :value="probe.t"
          :options="[
            { label: 'Ping', value: 'icmp' },
            { label: 'DNS', value: 'dns' },
            { label: 'HTTP / HTTPS', value: 'http' },
          ]"
          @update:value="changeKind(group, i, $event)"
        />
        <n-button
          :disabled="group.targets.length <= 1"
          @click="
            group.targets.splice(i, 1);
            group.quorum = Math.min(group.quorum, group.targets.length);
          "
          >−</n-button
        >
      </n-flex>
      <n-input
        v-if="probe.t === 'icmp'"
        v-model:value="probe.address"
        placeholder="IPv4 / IPv6"
      />
      <template v-if="probe.t === 'dns'">
        <n-input
          v-model:value="probe.server"
          :placeholder="t('network.health_check.dns_ip')"
        />
        <n-input
          v-model:value="probe.domain"
          :placeholder="t('network.health_check.dns_domain')"
          style="margin-top: 8px"
        />
      </template>
      <template v-if="probe.t === 'http'">
        <n-input
          v-model:value="probe.url"
          placeholder="https://www.baidu.com"
        />
        <n-input
          v-model:value="probe.dns_server"
          :placeholder="t('network.health_check.dns_ip')"
          style="margin-top: 8px"
        />
      </template>
    </n-card>
    <n-button
      size="small"
      :disabled="group.targets.length >= 4"
      @click="addTarget(group)"
      >{{ t("network.health_check.add_target") }}</n-button
    >
  </n-card>
  <n-flex style="margin-bottom: 16px">
    <n-button
      :disabled="groups.length >= 4"
      @click="
        groups.push({ name: 'IPv4', quorum: 1, targets: [target('dns')] })
      "
      >+ IPv4</n-button
    >
    <n-button
      :disabled="groups.length >= 4"
      @click="
        groups.push({ name: 'IPv6', quorum: 1, targets: [target('dns', true)] })
      "
      >+ IPv6</n-button
    >
  </n-flex>
</template>
