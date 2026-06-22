<script setup lang="ts">
import { WarningFilled } from "@vicons/carbon";
import { useI18n } from "vue-i18n";
import { computed, ref } from "vue";

const { t } = useI18n();
const show = ref(false);

const sup = (k: string) => t("geo_editor.geo_site.adguard_rule_info." + k);
const desc = (k: string) => sup(k + "_desc");
const noticeText = computed(() =>
  t("geo_editor.geo_site.adguard_limit_notice"),
);

interface RuleRow {
  rule: string;
  reason: string;
}

const supportedRules = computed<RuleRow[]>(() => [
  { rule: "||domain^", reason: desc("supported_1") },
  { rule: "||domain^$important", reason: desc("supported_2") },
  {
    rule: "0.0.0.0 domain / 127.0.0.1 domain / :: domain / ::1 domain",
    reason: desc("supported_3"),
  },
  { rule: "domain.com / domain.com$important", reason: desc("supported_4") },
]);

const skippedRules = computed<RuleRow[]>(() => [
  { rule: "@@... / $badfilter", reason: desc("skipped_1") },
  {
    rule: "$third-party / $3p / $domain= / $denyallow= / $to= / $client= / $dnstype= / $document / $image / $script / $dnsrewrite",
    reason: desc("skipped_2"),
  },
  { rule: "||domain.com/path^ / |https://domain|", reason: desc("skipped_3") },
  { rule: "## / #@# / #?#", reason: desc("skipped_4") },
  { rule: "/pattern/", reason: desc("skipped_5") },
  { rule: "! / #", reason: desc("skipped_6") },
]);
</script>

<template>
  <n-popover trigger="hover">
    <template #trigger>
      <n-button text :title="sup('title')" @click.stop="show = true">
        <template #icon>
          <n-icon size="18" color="#f0a020"><WarningFilled /></n-icon>
        </template>
      </n-button>
    </template>
    <div
      style="max-width: 340px; font-size: 12px; cursor: pointer"
      @click="show = true"
    >
      <n-text depth="2">{{ noticeText }}</n-text>
      <n-text type="info" depth="3" style="display: block; margin-top: 4px">{{
        sup("click_hint")
      }}</n-text>
    </div>
  </n-popover>
  <n-modal v-model:show="show" style="max-width: 520px">
    <n-card size="small" closable :title="sup('title')" @close="show = false">
      <n-flex vertical :size="10">
        <n-flex vertical :size="4">
          <n-text type="success" strong style="font-size: 13px">{{
            sup("supported_title")
          }}</n-text>
          <n-table :bordered="false" size="small">
            <thead>
              <tr>
                <th style="width: 200px">{{ sup("col_rule") }}</th>
                <th>{{ sup("col_mapping") }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="r in supportedRules" :key="r.rule">
                <td>
                  <code>{{ r.rule }}</code>
                </td>
                <td>{{ r.reason }}</td>
              </tr>
            </tbody>
          </n-table>
        </n-flex>

        <n-flex vertical :size="4">
          <n-text type="error" strong style="font-size: 13px">{{
            sup("skipped_title")
          }}</n-text>
          <n-table :bordered="false" size="small">
            <thead>
              <tr>
                <th style="width: 200px">{{ sup("col_rule") }}</th>
                <th>{{ sup("col_reason") }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="r in skippedRules" :key="r.rule">
                <td>
                  <code>{{ r.rule }}</code>
                </td>
                <td>{{ r.reason }}</td>
              </tr>
            </tbody>
          </n-table>
        </n-flex>

        <n-alert type="info" :show-icon="false" style="font-size: 12px">
          {{ sup("reason") }}
        </n-alert>
      </n-flex>
    </n-card>
  </n-modal>
</template>
