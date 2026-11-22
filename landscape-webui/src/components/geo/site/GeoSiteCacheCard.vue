<script setup lang="ts">
import type { GeoFileCacheKey } from "@landscape-router/types/api/schemas";
import { useI18n } from "vue-i18n";
import { useFrontEndStore } from "@/stores/front_end_config";
import { mask_string } from "@/lib/common";

const { t } = useI18n();

const frontEndStore = useFrontEndStore();
const emit = defineEmits<{ details: [entry: GeoFileCacheKey] }>();

interface Prop {
  geo_site: GeoFileCacheKey;
}
defineProps<Prop>();
</script>
<template>
  <n-card class="box" size="small" style="margin: 5px 0px">
    <n-flex justify="space-between">
      <n-flex>
        <n-flex>
          <n-tag :bordered="false">
            {{
              frontEndStore.presentation_mode
                ? mask_string(geo_site.name)
                : geo_site.name
            }}
          </n-tag>
        </n-flex>

        <n-flex>
          {{
            frontEndStore.presentation_mode
              ? mask_string(geo_site.key)
              : geo_site.key
          }}
        </n-flex>
      </n-flex>
      <n-flex>
        <n-button
          size="small"
          type="warning"
          secondary
          @click="emit('details', geo_site)"
        >
          {{ t("common.details") }}
        </n-button>
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
