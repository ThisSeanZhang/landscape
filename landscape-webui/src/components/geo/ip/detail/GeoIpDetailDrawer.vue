<script setup lang="ts">
import { get_geo_ip_cache_detail } from "@/api/geo/ip";
import type {
  GeoConfigKey,
  GeoIpConfig,
} from "@landscape-router/types/api/schemas";
import { onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
const { t } = useI18n();

const key = defineModel<GeoConfigKey>("geo_key", {
  required: true,
});
const show = defineModel<boolean>("show", { required: true });

const config = ref<GeoIpConfig>();

async function refresh() {
  config.value = await get_geo_ip_cache_detail(key.value);
}
</script>
<template>
  <n-drawer
    @after-enter="refresh"
    v-model:show="show"
    width="500px"
    placement="right"
  >
    <n-drawer-content :title="t('geo.detail_drawer.rule_details')" closable>
      <n-virtual-list v-if="config" :item-size="60" :items="config.values">
        <template #default="{ item }">
          <n-card
            style="margin: 5px 0px; height: 50px"
            :title="`${item.ip}/${item.prefix}`"
            size="small"
          >
          </n-card>
        </template>
      </n-virtual-list>
    </n-drawer-content>
  </n-drawer>
</template>
