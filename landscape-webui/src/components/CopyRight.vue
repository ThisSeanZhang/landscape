<script setup lang="ts">
import { Information, Api, Book } from "@vicons/carbon";
import { useI18n } from "vue-i18n";
import { useRouter } from "vue-router";

const icon = defineModel<boolean>("icon", { default: false });
const router = useRouter();
const { t } = useI18n();
</script>
<template>
  <n-flex
    align="center"
    :justify="icon ? 'start' : 'center'"
    :style="{ padding: '0 10px', width: icon ? '100%' : undefined }"
  >
    <n-flex
      v-if="icon"
      align="center"
      justify="space-between"
      style="width: 100%"
      :wrap="false"
      :size="[5, 5]"
    >
      <n-tooltip trigger="hover">
        <template #trigger>
          <n-button
            text
            tag="a"
            href="https://landscape.whileaway.dev/"
            target="_blank"
            rel="noopener noreferrer"
          >
            <n-icon>
              <Book />
            </n-icon>
          </n-button>
        </template>
        {{ t("about.documentation") }}
      </n-tooltip>
      <n-tooltip trigger="hover">
        <template #trigger>
          <n-button
            text
            tag="a"
            href="/api/docs"
            target="_blank"
            rel="noopener noreferrer"
          >
            <n-icon>
              <Api />
            </n-icon>
          </n-button>
        </template>
        {{ t("about.api_docs") }}
      </n-tooltip>
      <n-tooltip trigger="hover">
        <template #trigger>
          <n-button text @click="router.push('/about')">
            <n-icon>
              <Information />
            </n-icon>
          </n-button>
        </template>
        {{ t("about.title") }}
      </n-tooltip>
    </n-flex>
    <n-flex v-else>
      <n-button
        text
        tag="a"
        href="https://github.com/ThisSeanZhang/landscape"
        target="_blank"
        rel="noopener noreferrer"
        type="primary"
      >
        {{ t("about.license_project_name") }}
      </n-button>
      {{ t("about.license_text") }}
      <n-button
        text
        tag="a"
        href="https://github.com/ThisSeanZhang/landscape/blob/main/LICENSE"
        target="_blank"
        rel="noopener noreferrer"
        type="primary"
        >{{ t("about.license_name") }}</n-button
      >
    </n-flex>
  </n-flex>
</template>
