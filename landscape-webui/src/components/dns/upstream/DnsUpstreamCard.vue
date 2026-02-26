<script setup lang="ts">
import { computed, ref } from "vue";
import type { DnsUpstreamConfig } from "@landscape-router/types/api/schemas";
import { DnsUpstreamModeTsEnum, upstream_mode_exhibit_name } from "@/lib/dns";
import { delete_dns_upstream } from "@/api/dns_rule/upstream";
import { useFrontEndStore } from "@/stores/front_end_config";
import { useI18n } from "vue-i18n";

const frontEndStore = useFrontEndStore();
const { t } = useI18n();
type Props = {
  rule: DnsUpstreamConfig;
  show_action?: boolean;
};

const props = withDefaults(defineProps<Props>(), {
  show_action: true,
});
const emit = defineEmits(["refresh"]);

const show_edit_modal = ref(false);
async function del() {
  if (props.rule.id) {
    await delete_dns_upstream(props.rule.id);
    emit("refresh");
  }
}

const domain = computed(() => {
  if (props.rule.mode.t === DnsUpstreamModeTsEnum.Plaintext) {
    return t("dns_editor.upstream_card.no_config");
  } else if (props.rule.mode.t === DnsUpstreamModeTsEnum.Https) {
    let url = props.rule.mode.http_endpoint ?? "/dns-query";
    return frontEndStore.MASK_INFO(`${props.rule.mode.domain}${url}`);
  } else {
    return frontEndStore.MASK_INFO(props.rule.mode.domain);
  }
});
</script>

<template>
  <n-card size="small">
    <template #header>
      <n-ellipsis>
        {{ rule.remark !== "" ? rule.remark : t("dns_editor.upstream_card.no_remark") }}
      </n-ellipsis>
    </template>
    <n-descriptions
      label-style="width: 81px"
      bordered
      label-placement="left"
      :column="2"
      size="small"
    >
      <n-descriptions-item :label="t('dns_editor.upstream_card.request_mode')">
        {{ upstream_mode_exhibit_name(rule.mode.t) }}
      </n-descriptions-item>

      <n-descriptions-item :label="t('dns_editor.upstream_card.request_port')">
        {{ frontEndStore.MASK_INFO(rule.port?.toString()) }}
      </n-descriptions-item>

      <n-descriptions-item span="2" :label="t('dns_editor.upstream_card.domain_addr')">
        {{ domain }}
      </n-descriptions-item>

      <n-descriptions-item span="2" :label="t('dns_editor.upstream_card.upstream_ip')">
        <n-scrollbar style="height: 90px">
          <n-flex>
            <n-flex v-for="ip in rule.ips">
              {{ frontEndStore.MASK_INFO(ip) }}
            </n-flex>
          </n-flex>
        </n-scrollbar>
      </n-descriptions-item>
    </n-descriptions>

    <template v-if="show_action" #header-extra>
      <n-flex>
        <n-button
          size="small"
          type="warning"
          secondary
          @click="show_edit_modal = true"
        >
          {{ t("dns_editor.upstream_card.edit") }}
        </n-button>

        <n-popconfirm @positive-click="del()">
          <template #trigger>
            <n-button size="small" type="error" secondary @click="">
              {{ t("dns_editor.upstream_card.delete") }}
            </n-button>
          </template>
          {{ t("dns_editor.upstream_card.confirm_delete") }}
        </n-popconfirm>
      </n-flex>
    </template>
  </n-card>
  <UpstreamEditModal
    @refresh="emit('refresh')"
    :rule_id="rule.id"
    v-model:show="show_edit_modal"
  >
  </UpstreamEditModal>
</template>
