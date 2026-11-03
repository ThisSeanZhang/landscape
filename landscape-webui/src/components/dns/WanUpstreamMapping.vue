<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { get_all_wan_links } from "@/api/service_wan_link";
import { get_dns_upstreams } from "@/api/dns_rule/upstream";
import type { DnsWanUpstream } from "@landscape-router/types/api/schemas";

const props = defineProps<{ readonly?: boolean }>();
const mappings = defineModel<DnsWanUpstream[]>({ required: true });
const { t } = useI18n();
const wans = ref<{ label: string; value: string }[]>([]);
const groups = ref<{ label: string; value: string; disabled: boolean }[]>([]);
const enabled = computed({
  get: () => mappings.value.length > 0,
  set: (value: boolean) => {
    mappings.value = value
      ? wans.value.map((wan) => ({ link_id: wan.value, upstream_id: "" }))
      : [];
  },
});
onMounted(async () => {
  const [links, upstreams] = await Promise.all([
    get_all_wan_links(),
    get_dns_upstreams(),
  ]);
  wans.value = links.map((wan) => ({
    label: wan.name || wan.attach_iface_name,
    value: wan.id,
  }));
  groups.value = upstreams
    .filter((u) => u.id)
    .map((u) => ({
      label: u.name || u.remark || u.id!,
      value: u.id!,
      disabled:
        !u.ips.length ||
        u.bind_config?.follow_flow != null ||
        !!u.bind_config?.wan_servers?.length ||
        !!u.bind_config?.bind_addr4 ||
        !!u.bind_config?.bind_addr6,
    }));
});
</script>

<template>
  <n-flex vertical style="width: 100%">
    <n-flex v-if="!props.readonly" align="center">
      <n-switch v-model:value="enabled" :disabled="!wans.length" />
      {{ t("dns.rule_edit.wan_groups") }}
    </n-flex>
    <n-alert v-if="enabled && !props.readonly" type="info" :show-icon="false">
      {{ t("dns.rule_edit.wan_groups_hint") }}
    </n-alert>
    <n-flex
      v-for="(mapping, index) in mappings"
      :key="index"
      align="center"
      :wrap="false"
    >
      <template v-if="props.readonly">
        <span>{{
          wans.find((wan) => wan.value === mapping.link_id)?.label ||
          mapping.link_id
        }}</span>
        <span>→</span>
        <span>{{
          groups.find((group) => group.value === mapping.upstream_id)?.label ||
          mapping.upstream_id
        }}</span>
      </template>
      <template v-else>
        <n-select
          v-model:value="mapping.link_id"
          :options="wans"
          style="width: 36%"
        />
        <n-select
          v-model:value="mapping.upstream_id"
          :options="groups"
          filterable
          style="flex: 1"
          :placeholder="t('dns.rule_edit.wan_group_select')"
        />
        <n-button size="small" @click="mappings.splice(index, 1)">{{
          t("common.delete")
        }}</n-button>
      </template>
    </n-flex>
    <n-button
      v-if="enabled && !props.readonly && mappings.length < wans.length"
      size="small"
      @click="mappings.push({ link_id: '', upstream_id: '' })"
    >
      {{ t("dns.rule_edit.wan_group_add") }}
    </n-button>
  </n-flex>
</template>
