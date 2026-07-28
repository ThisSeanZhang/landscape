<script lang="ts" setup>
import {
  get_lan_ipv6_assigned_ips,
  get_all_lan_ipv6_dhcpv6_assigned,
} from "@/api/service_lan_ipv6";
import type {
  IPv6NAInfo,
  DHCPv6OfferInfo,
} from "@landscape-router/types/api/schemas";
import { onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import DHCPv6AssignedTable from "@/components/dhcp_v6/DHCPv6AssignedTable.vue";

const { t } = useI18n();

onMounted(async () => {
  await get_info();
});

const loading = ref(false);
const infos = ref<{ label: string; value: IPv6NAInfo | null }[]>([]);
const dhcpv6_infos = ref<{ label: string; value: DHCPv6OfferInfo }[]>([]);

async function get_info() {
  try {
    loading.value = true;
    let req_data = await get_lan_ipv6_assigned_ips();
    const result = [];
    for (const [label, value] of req_data) {
      result.push({
        label,
        value,
      });
    }
    result.sort((a, b) => a.label.localeCompare(b.label));
    infos.value = result;

    // DHCPv6 assigned
    let dhcpv6_data = await get_all_lan_ipv6_dhcpv6_assigned();
    const dhcpv6_result = [];
    for (const [label, value] of dhcpv6_data) {
      if (value) {
        dhcpv6_result.push({ label, value });
      }
    }
    dhcpv6_result.sort((a, b) => a.label.localeCompare(b.label));
    dhcpv6_infos.value = dhcpv6_result;
  } finally {
    loading.value = false;
  }
}
</script>

<template>
  <n-flex vertical style="flex: 1">
    <n-alert type="info">
      {{ t("common.list_no_auto_refresh") }}
      <n-tag :bordered="false" type="warning">STALE</n-tag>
    </n-alert>
    <n-flex>
      <n-button :loading="loading" @click="get_info">{{
        t("common.refresh")
      }}</n-button>
    </n-flex>
    <n-flex v-if="infos.length > 0">
      <LanIPv6ShowItem
        v-for="(data, index) in infos"
        :key="index"
        :config="data.value"
        :iface_name="data.label"
      />
    </n-flex>
    <n-empty style="flex: 1" v-else></n-empty>

    <!-- DHCPv6 Assigned -->
    <template v-if="dhcpv6_infos.length > 0">
      <n-divider title-placement="left">
        {{ t("dhcp_v6.dhcpv6_assigned_info") }}
      </n-divider>
      <n-flex>
        <DHCPv6AssignedTable
          v-for="(data, index) in dhcpv6_infos"
          :key="'dhcpv6-' + index"
          :iface_name="data.label"
          :info="data.value"
        />
      </n-flex>
    </template>
  </n-flex>
</template>
