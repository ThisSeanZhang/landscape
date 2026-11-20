<script setup lang="ts">
import { useCapabilityStore } from "@/stores/capability";
import { useMetricConfigStore } from "@/stores/metric_config";
import { useMessage } from "naive-ui";
import type { FormInst, FormRules } from "naive-ui";
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";

const metricStore = useMetricConfigStore();
const message = useMessage();
const { t } = useI18n();
const formRef = ref<FormInst | null>(null);
const { kind } = defineProps<{ kind: "connect" | "dns" }>();
const block = computed(() => metricStore[kind]);
const capabilities = useCapabilityStore();
const backendOptions = computed(() => [
  { label: t("config.metric_mode_memory"), value: "memory" },
  ...(capabilities.HAS("metric_persistent")
    ? [{ label: t("config.metric_mode_persistent"), value: "sqlite" }]
    : []),
]);
const dbCapRule = (): NonNullable<FormRules[string]> => {
  return {
    validator: (_rule, value: number | undefined) => {
      if (value === undefined || value === null || value === 0 || value >= 16) {
        return true;
      }
      return new Error(t("config.db_cap_min_hint"));
    },
    trigger: ["blur", "change"],
  };
};

const rules: FormRules = {
  "store.max_mb": dbCapRule(),
};

async function handleSaveMetric() {
  try {
    await formRef.value?.validate();
  } catch {
    return;
  }
  try {
    await block.value.save();
    message.success(t("config.save_success"));
  } catch (e: any) {
    if (e.response?.status === 409) {
      message.error(t("config.conflict"));
    } else {
      message.error(t("config.save_failed") + ": " + e.message);
    }
  }
}
</script>

<template>
  <n-card
    :title="t('config.' + kind + '_metric_title')"
    segmented
    :id="kind + '-metric-config'"
  >
    <template #header-extra>
      <n-button
        type="primary"
        :disabled="block.hash === null"
        :loading="block.saving"
        @click="handleSaveMetric"
        >{{ t("config.save_metric") }}</n-button
      >
    </template>
    <n-form
      ref="formRef"
      :model="block.config"
      :rules="rules"
      :disabled="block.hash === null || block.saving"
      label-placement="left"
      label-width="120"
    >
      <n-form-item :label="t('config.metric_enabled')"
        ><n-switch
          :value="block.config.enabled ?? true"
          @update:value="block.config.enabled = $event"
      /></n-form-item>
      <n-form-item
        :label="t('config.metric_backend')"
        v-if="
          capabilities.HAS('metric_persistent') ||
          block.config.store.backend === 'sqlite'
        "
      >
        <n-select
          :value="block.config.store.backend ?? 'sqlite'"
          :options="backendOptions"
          @update:value="block.config.store.backend = $event"
        />
      </n-form-item>
      <template v-if="kind === 'connect'">
        <n-divider title-placement="left">
          {{ t("config.conn_retention_mins") }}
        </n-divider>
        <n-grid x-gap="12" :cols="2">
          <n-gi>
            <n-form-item :label="t('config.connect_second_window_mins')">
              <n-input-number
                :value="metricStore.connect.config.second_window_minutes"
                @update:value="
                  metricStore.connect.config.second_window_minutes =
                    $event ?? undefined
                "
                :min="1"
                :max="60"
                placeholder="5"
                style="width: 100%"
              />
              <template #feedback>
                {{ t("config.connect_second_window_mins_desc") }}
              </template>
            </n-form-item>
          </n-gi>
          <n-gi>
            <n-form-item :label="t('config.conn_retention_minute_days')">
              <n-input-number
                :value="metricStore.connect.config.retention_1m_days"
                @update:value="
                  metricStore.connect.config.retention_1m_days =
                    $event ?? undefined
                "
                :min="1"
                :max="365"
                placeholder="1"
                style="width: 100%"
              />
              <template #feedback>
                {{ t("config.conn_retention_minute_days_desc") }}
              </template>
            </n-form-item>
          </n-gi>
          <n-gi>
            <n-form-item :label="t('config.conn_retention_hour_days')">
              <n-input-number
                :value="metricStore.connect.config.retention_1h_days"
                @update:value="
                  metricStore.connect.config.retention_1h_days =
                    $event ?? undefined
                "
                :min="1"
                :max="365"
                placeholder="7"
                style="width: 100%"
              />
              <template #feedback>
                {{ t("config.conn_retention_hour_days_desc") }}
              </template>
            </n-form-item>
          </n-gi>
          <n-gi>
            <n-form-item :label="t('config.conn_retention_day_days')">
              <n-input-number
                :value="metricStore.connect.config.retention_1d_days"
                @update:value="
                  metricStore.connect.config.retention_1d_days =
                    $event ?? undefined
                "
                :min="1"
                :max="3650"
                placeholder="30"
                style="width: 100%"
              />
              <template #feedback>
                {{ t("config.conn_retention_day_days_desc") }}
              </template>
            </n-form-item>
          </n-gi>
        </n-grid>

        <n-divider title-placement="left">
          {{ t("config.conn_detail_settings") }}
        </n-divider>
        <n-grid x-gap="12" :cols="2">
          <n-gi>
            <n-form-item :label="t('config.conn_summary_retention_days')">
              <n-input-number
                :value="metricStore.connect.config.summary_retention_days"
                @update:value="
                  metricStore.connect.config.summary_retention_days =
                    $event ?? undefined
                "
                :min="1"
                :max="3650"
                placeholder="30"
                style="width: 100%"
              />
              <template #feedback>
                {{ t("config.conn_summary_retention_days_desc") }}
              </template>
            </n-form-item>
          </n-gi>
          <n-gi>
            <n-form-item :label="t('config.conn_summary_max_rows')">
              <n-input-number
                :value="metricStore.connect.config.summary_max_rows"
                @update:value="
                  metricStore.connect.config.summary_max_rows =
                    $event ?? undefined
                "
                :min="0"
                :max="100000000"
                placeholder="500000"
                style="width: 100%"
              />
              <template #feedback>
                {{ t("config.conn_summary_max_rows_desc") }}
              </template>
            </n-form-item>
          </n-gi>
          <n-gi>
            <n-form-item
              :label="t('config.connect_db_max_mb')"
              path="store.max_mb"
            >
              <n-input-number
                :value="metricStore.connect.config.store.max_mb"
                @update:value="
                  metricStore.connect.config.store.max_mb = $event ?? undefined
                "
                :min="0"
                :max="1048576"
                placeholder="512"
                style="width: 100%"
              />
              <template #feedback>
                {{ t("config.connect_db_max_mb_desc") }}
              </template>
            </n-form-item>
          </n-gi>
        </n-grid> </template
      ><template v-else>
        <n-divider title-placement="left">
          {{ t("config.dns_retention_days") }}
        </n-divider>
        <n-form-item :label="t('config.dns_retention_days')">
          <n-input-number
            :value="metricStore.dns.config.retention_days"
            @update:value="
              metricStore.dns.config.retention_days = $event ?? undefined
            "
            :min="1"
            :max="365"
            placeholder="7"
            style="width: 200px"
          />
          <template #feedback>
            {{ t("config.dns_retention_days_desc") }}
          </template>
        </n-form-item>
        <n-grid x-gap="12" :cols="2">
          <n-gi>
            <n-form-item :label="t('config.dns_1m_retention_days')">
              <n-input-number
                :value="metricStore.dns.config.retention_1m_days"
                @update:value="
                  metricStore.dns.config.retention_1m_days = $event ?? undefined
                "
                :min="1"
                :max="365"
                placeholder="30"
                style="width: 100%"
              />
              <template #feedback>
                {{ t("config.dns_1m_retention_days_desc") }}
              </template>
            </n-form-item>
          </n-gi>
          <n-gi>
            <n-form-item :label="t('config.dns_db_max_mb')" path="store.max_mb">
              <n-input-number
                :value="metricStore.dns.config.store.max_mb"
                @update:value="
                  metricStore.dns.config.store.max_mb = $event ?? undefined
                "
                :min="0"
                :max="1048576"
                placeholder="1024"
                style="width: 100%"
              />
              <template #feedback>
                {{ t("config.dns_db_max_mb_desc") }}
              </template>
            </n-form-item>
          </n-gi>
        </n-grid>
      </template>
      <n-divider title-placement="left">
        {{ t("config.performance_settings") }}
      </n-divider>
      <n-grid x-gap="12" :cols="2">
        <n-gi>
          <n-form-item :label="t('config.write_flush_interval')">
            <n-input-number
              :value="block.config.store.write_flush_interval_secs"
              @update:value="
                block.config.store.write_flush_interval_secs =
                  $event ?? undefined
              "
              :min="1"
              :max="3600"
              placeholder="30"
              style="width: 100%"
            />
            <template #feedback>
              {{ t("config.write_flush_interval_desc") }}
            </template>
          </n-form-item>
        </n-gi>
        <n-gi v-if="kind === 'connect'">
          <n-form-item :label="t('config.write_batch_size')">
            <n-input-number
              :value="metricStore.connect.config.write_batch_size"
              @update:value="
                metricStore.connect.config.write_batch_size =
                  $event ?? undefined
              "
              :min="100"
              :max="50000"
              placeholder="20000"
              style="width: 100%"
            />
            <template #feedback>
              {{ t("config.write_batch_size_desc") }}
            </template>
          </n-form-item>
        </n-gi>
      </n-grid>

      <n-divider title-placement="left">
        {{ t("config.maintenance_settings") }}
      </n-divider>
      <n-grid x-gap="12" :cols="2">
        <n-gi>
          <n-form-item :label="t('config.cleanup_interval')">
            <n-input-number
              :value="block.config.store.cleanup_interval_secs"
              @update:value="
                block.config.store.cleanup_interval_secs = $event ?? undefined
              "
              :min="60"
              :max="86400"
              placeholder="300"
              style="width: 100%"
            />
            <template #feedback>
              {{ t("config.cleanup_interval_desc") }}
            </template>
          </n-form-item>
        </n-gi>
        <n-gi>
          <n-form-item :label="t('config.cleanup_budget')">
            <n-input-number
              :value="block.config.store.cleanup_time_budget_secs"
              @update:value="
                block.config.store.cleanup_time_budget_secs =
                  $event ?? undefined
              "
              :min="1"
              :max="60"
              placeholder="2"
              style="width: 100%"
            />
            <template #feedback>
              {{ t("config.cleanup_budget_desc") }}
            </template>
          </n-form-item>
        </n-gi>
        <n-gi>
          <n-form-item :label="t('config.cleanup_slice_window')">
            <n-input-number
              :value="block.config.store.cleanup_slice_window_secs"
              @update:value="
                block.config.store.cleanup_slice_window_secs =
                  $event ?? undefined
              "
              :min="10"
              :max="3600"
              placeholder="300"
              style="width: 100%"
            />
            <template #feedback>
              {{ t("config.cleanup_slice_window_desc") }}
            </template>
          </n-form-item>
        </n-gi>
      </n-grid>
    </n-form>
  </n-card>
</template>
