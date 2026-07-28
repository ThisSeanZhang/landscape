<script setup lang="ts">
import { useI18n } from "vue-i18n";
import type { LanIPv6ServiceConfigV2 } from "@landscape-router/types/api/schemas";

const { t } = useI18n({ useScope: "global" });

const config = defineModel<LanIPv6ServiceConfigV2>("service-config", {
  required: true,
});

function initialize_dhcpv6_if_needed() {
  if (!config.value?.config?.dhcpv6) {
    if (config.value?.config) {
      config.value.config.dhcpv6 = {
        enable: false,
      };
    }
  }
}

function initialize_ia_na(enable: boolean) {
  if (!config.value?.config) return;

  if (!config.value.config.dhcpv6) {
    config.value.config.dhcpv6 = {
      enable: false,
    };
  }

  if (enable) {
    config.value.config.dhcpv6.ia_na = {
      max_prefix_len: 64,
      pool_start: 256,
      preferred_lifetime: 300,
      valid_lifetime: 600,
    };
  } else {
    config.value.config.dhcpv6.ia_na = undefined;
  }
}

function initialize_ia_pd(enable: boolean) {
  if (!config.value?.config) return;

  if (!config.value.config.dhcpv6) {
    config.value.config.dhcpv6 = {
      enable: false,
    };
  }

  if (enable) {
    config.value.config.dhcpv6.ia_pd = {
      delegate_prefix_len: 64,
      preferred_lifetime: 300,
      valid_lifetime: 600,
    };
  } else {
    config.value.config.dhcpv6.ia_pd = undefined;
  }
}

function update_ia_na_field(field: string, value: number | null) {
  if (!config.value?.config) return;

  initialize_dhcpv6_if_needed();

  const dhcpv6 = config.value.config.dhcpv6;
  if (!dhcpv6) return;

  if (!dhcpv6.ia_na) {
    dhcpv6.ia_na = {
      max_prefix_len: 64,
      pool_start: 256,
      preferred_lifetime: 300,
      valid_lifetime: 600,
    };
  }

  if (typeof value === "number") {
    (dhcpv6.ia_na as any)[field] = value;
  }
}

function update_ia_pd_field(field: string, value: number | null) {
  if (!config.value?.config) return;

  initialize_dhcpv6_if_needed();

  const dhcpv6 = config.value.config.dhcpv6;
  if (!dhcpv6) return;

  if (!dhcpv6.ia_pd) {
    dhcpv6.ia_pd = {
      delegate_prefix_len: 64,
      preferred_lifetime: 300,
      valid_lifetime: 600,
    };
  }

  if (typeof value === "number") {
    (dhcpv6.ia_pd as any)[field] = value;
  }
}
</script>

<template>
  <n-card style="flex: 3; min-width: 0" size="small" :bordered="false">
    <template #header>
      <div style="display: flex; align-items: center; gap: 12px; flex: 1">
        <span>{{ t("lan_ipv6.dhcpv6_server") }}</span>
        <n-switch
          style="margin-left: auto"
          :value="!!config?.config.dhcpv6?.enable"
          @update:value="
            (val: boolean) => {
              initialize_dhcpv6_if_needed();
              if (config?.config?.dhcpv6) {
                config.config.dhcpv6.enable = val;
              }
            }
          "
        >
          <template #checked> {{ t("lan_ipv6.enabled") }} </template>
          <template #unchecked> {{ t("lan_ipv6.disabled") }} </template>
        </n-switch>
      </div>
    </template>

    <n-flex :gap="12" align="start">
      <!-- Left: IA_NA -->
      <div style="flex: 1; min-width: 0">
        <n-divider title-placement="left" style="margin: 0 0 8px">
          {{ t("lan_ipv6.ia_na") }}
        </n-divider>
        <n-grid :x-gap="12" :y-gap="8" cols="2" item-responsive>
          <n-form-item-gi span="2" :label="t('lan_ipv6.enable_ia_na')">
            <n-switch
              :value="!!config?.config.dhcpv6?.ia_na"
              @update:value="initialize_ia_na"
            />
          </n-form-item-gi>
          <template v-if="config?.config.dhcpv6?.ia_na">
            <n-form-item-gi span="2">
              <template #label>
                <Notice>
                  {{ t("lan_ipv6.ia_na_max_prefix_len") }}
                  <template #msg>
                    {{ t("lan_ipv6.ia_na_max_prefix_len_desc") }}
                  </template>
                </Notice>
              </template>
              <n-input-number
                style="flex: 1"
                :value="config?.config.dhcpv6?.ia_na?.max_prefix_len ?? 64"
                @update:value="
                  (val: number | null) =>
                    update_ia_na_field('max_prefix_len', val)
                "
                :min="1"
                :max="127"
              />
            </n-form-item-gi>
            <n-form-item-gi span="2">
              <template #label>
                <Notice>
                  {{ t("lan_ipv6.ia_na_pool_start") }}
                  <template #msg>
                    {{ t("lan_ipv6.ia_na_pool_start_desc") }}
                  </template>
                </Notice>
              </template>
              <n-input-number
                style="flex: 1"
                :value="config?.config.dhcpv6?.ia_na?.pool_start ?? 256"
                @update:value="
                  (val: number | null) => update_ia_na_field('pool_start', val)
                "
                :min="1"
              />
            </n-form-item-gi>
          </template>
        </n-grid>
      </div>

      <!-- Right: IA_PD -->
      <div style="flex: 1; min-width: 0">
        <n-divider title-placement="left" style="margin: 0 0 8px">
          {{ t("lan_ipv6.ia_pd") }}
        </n-divider>
        <n-grid :x-gap="12" :y-gap="8" cols="2" item-responsive>
          <n-form-item-gi span="2" :label="t('lan_ipv6.enable_ia_pd')">
            <n-switch
              :value="!!config?.config.dhcpv6?.ia_pd"
              @update:value="initialize_ia_pd"
            />
          </n-form-item-gi>
          <template v-if="config?.config.dhcpv6?.ia_pd">
            <n-form-item-gi span="2">
              <template #label>
                <Notice>
                  {{ t("lan_ipv6.ia_pd_delegate_prefix_len") }}
                  <template #msg>
                    {{ t("lan_ipv6.ia_pd_delegate_prefix_len_desc") }}
                  </template>
                </Notice>
              </template>
              <n-input-number
                style="flex: 1"
                :value="config?.config.dhcpv6?.ia_pd?.delegate_prefix_len ?? 64"
                @update:value="
                  (val: number | null) =>
                    update_ia_pd_field('delegate_prefix_len', val)
                "
                :min="1"
                :max="128"
              />
            </n-form-item-gi>
          </template>
        </n-grid>
      </div>
    </n-flex>
  </n-card>
</template>
