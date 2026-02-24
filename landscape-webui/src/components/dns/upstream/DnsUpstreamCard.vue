<script setup lang="ts">
import { computed, ref } from "vue";
import type { DnsUpstreamConfig } from "@landscape-router/types/api/schemas";
import { DnsUpstreamModeTsEnum, upstream_mode_exhibit_name } from "@/lib/dns";
import { delete_dns_upstream } from "@/api/dns_rule/upstream";
import { useFrontEndStore } from "@/stores/front_end_config";

const frontEndStore = useFrontEndStore();
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
    return "无配置";
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
        {{ rule.remark !== "" ? rule.remark : "无备注" }}
      </n-ellipsis>
    </template>
    <!-- {{ rule }} -->
    <n-descriptions
      label-style="width: 81px"
      bordered
      label-placement="left"
      :column="2"
      size="small"
    >
      <!-- <n-descriptions-item label="应用于">
        <n-flex v-if="rule.apply_flows.length > 0">
          <n-tag v-for="value in rule.apply_flows" :bordered="false">
            {{ value === 0 ? "默认流" : value }}
          </n-tag>
        </n-flex>
        <n-flex v-else>
          <span style="min-height: 28px">全部 Flow </span>
        </n-flex>
      </n-descriptions-item> -->

      <n-descriptions-item label="请求方式">
        {{ upstream_mode_exhibit_name(rule.mode.t) }}
      </n-descriptions-item>

      <n-descriptions-item label="请求端口">
        {{ frontEndStore.MASK_INFO(rule.port?.toString()) }}
      </n-descriptions-item>

      <n-descriptions-item span="2" label="域名地址">
        {{ domain }}
      </n-descriptions-item>

      <n-descriptions-item span="2" label="上游 IP">
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
          编辑
        </n-button>

        <n-popconfirm @positive-click="del()">
          <template #trigger>
            <n-button size="small" type="error" secondary @click="">
              删除
            </n-button>
          </template>
          确定删除吗
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
