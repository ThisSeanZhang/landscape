<script setup lang="ts">
import { GeoIpConfig } from "landscape-types/common/geo_ip";
import { ref } from "vue";
import { useFrontEndStore } from "@/stores/front_end_config";
import { mask_string } from "@/lib/common";

const frontEndStore = useFrontEndStore();
const emit = defineEmits(["refresh"]);

interface Prop {
  geo_site: GeoIpConfig;
}
const props = defineProps<Prop>();
const show_detail_modal = ref(false);
</script>
<template>
  <n-card class="box" style="margin: 5px 0px" size="small">
    <n-flex justify="space-between">
      <n-flex>
        <n-flex>
          <n-tag :bordered="false">
            {{ frontEndStore.MASK_INFO(geo_site.name) }}
          </n-tag>
        </n-flex>

        <n-flex>
          {{ frontEndStore.MASK_INFO(geo_site.key) }}
        </n-flex>
      </n-flex>

      <n-flex>
        <n-button
          size="small"
          type="warning"
          secondary
          @click="show_detail_modal = true"
        >
          详情
        </n-button>
        <GeoIpDetailDrawer :geo_key="geo_site" v-model:show="show_detail_modal">
        </GeoIpDetailDrawer>
      </n-flex>
    </n-flex>
  </n-card>
</template>

<style scoped>
.box {
  border: 2px solid transparent;
  transition: border-color 0.25s ease;
}

.box:hover {
  border-color: #4fa3ff; /* 你想要的亮色 */
}
</style>
