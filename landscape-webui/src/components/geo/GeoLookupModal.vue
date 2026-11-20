<script setup lang="ts">
import type {
  GeoIpLookupResult,
  GeoSiteLookupResult,
  GeoSiteFileConfig,
  IpConfig,
} from "@landscape-router/types/api/schemas";
import { lookup_geo_ip_address } from "@/api/geo/ip";

import { lookup_geo_site_domain } from "@/api/geo/site";

import { ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { useDialog } from "naive-ui";

const props = defineProps<{ mode: "site" | "ip" }>();
const show = defineModel<boolean>("show", { required: true });
const { t } = useI18n();
const dialog = useDialog();

const input = ref("");
const loading = ref(false);
const searched = ref(false);
const results = ref<Array<GeoSiteLookupResult | GeoIpLookupResult>>([]);

watch(show, (visible) => {
  if (visible) {
    input.value = "";
    results.value = [];
    searched.value = false;
  }
});

function valueLabel(value: GeoSiteFileConfig | IpConfig) {
  return "match_type" in value
    ? `${value.match_type}: ${value.value}`
    : `${value.ip}/${value.prefix}`;
}

function cleanDomainInput(raw: string) {
  let value = raw.trim().replace(/^[a-zA-Z]+:\/\//, "");
  value = value.split(/[/?#]/)[0].trim();
  if (value.includes(":") && !value.includes("::") && !value.startsWith("[")) {
    value = value.split(":")[0];
  }
  return value.toLowerCase();
}

async function executeLookup(value: string) {
  loading.value = true;
  try {
    results.value =
      props.mode === "site"
        ? await lookup_geo_site_domain(value)
        : await lookup_geo_ip_address(value);
    searched.value = true;
  } catch {
    results.value = [];
    searched.value = false;
  } finally {
    loading.value = false;
  }
}

async function lookup() {
  const raw = input.value.trim();
  if (!raw) return;

  if (props.mode === "site") {
    const domain = cleanDomainInput(raw);
    if (!domain) return;
    input.value = domain;

    if (!domain.includes(".")) {
      const suggested = `${domain}.com`;
      dialog.info({
        title: t("geo.lookup.domain_notice_title"),
        content: t("geo.lookup.domain_notice_content", {
          example: "baidu.com",
          suggested,
        }),
        positiveText: t("geo.lookup.domain_notice_positive", {
          domain: suggested,
        }),
        negativeText: t("common.cancel"),
        onPositiveClick: () => {
          input.value = suggested;
          void executeLookup(suggested);
        },
      });
      return;
    }

    await executeLookup(domain);
    return;
  }

  await executeLookup(raw);
}
</script>

<template>
  <n-modal
    v-model:show="show"
    preset="card"
    style="width: 600px"
    :title="t(`geo.lookup.${mode}_title`)"
    :bordered="false"
    :auto-focus="false"
  >
    <n-flex vertical>
      <n-input-group>
        <n-input
          v-model:value="input"
          clearable
          :placeholder="t(`geo.lookup.${mode}_placeholder`)"
          @keyup.enter="lookup"
        />
        <n-button type="primary" :loading="loading" @click="lookup">
          {{ t("geo.lookup.action") }}
        </n-button>
      </n-input-group>

      <n-spin :show="loading">
        <n-list v-if="results.length" bordered>
          <n-list-item
            v-for="result in results"
            :key="`${result.key.name}/${result.key.key}`"
          >
            <n-flex vertical size="small">
              <n-text strong>{{ result.key.name }}/{{ result.key.key }}</n-text>
              <n-flex size="small" wrap>
                <n-tag
                  v-for="value in result.values"
                  :key="valueLabel(value)"
                  size="small"
                  :bordered="false"
                >
                  {{ valueLabel(value) }}
                </n-tag>
              </n-flex>
            </n-flex>
          </n-list-item>
        </n-list>
        <n-empty
          v-else-if="searched"
          :description="t('geo.lookup.no_result')"
        />
      </n-spin>
    </n-flex>
  </n-modal>
</template>
