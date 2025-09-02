<script setup lang="ts">
import { ref } from "vue";
import { useMessage } from "naive-ui";
import { SearchLocate } from "@vicons/carbon";
import { CheckChainDnsResult, CheckDnsReq } from "@/rust_bindings/dns";
import { check_domain } from "@/api/dns_service";
import { LandscapeDnsRecordType } from "@/rust_bindings/common/dns_record_type";
import { DnsRule } from "@/lib/dns";
import { get_dns_rule } from "@/api/dns_rule";
import { DNSRedirectRule } from "@/rust_bindings/common/dns_redirect";
import { get_dns_redirect } from "@/api/dns_rule/redirect";
const message = useMessage();

interface Props {
  flow_id?: number;
}

const props = withDefaults(defineProps<Props>(), {
  flow_id: 0,
});

const show = defineModel<boolean>("show", { required: true });
const req = ref<CheckDnsReq>({
  flow_id: 0,
  domain: "",
  record_type: "A",
});
const result = ref<CheckChainDnsResult>({
  redirect_id: null,
  rule_id: null,
  records: null,
  cache_records: null,
});

async function init_req() {
  req.value = {
    flow_id: props.flow_id,
    domain: "",
    record_type: "A",
  };
  result.value = {
    redirect_id: null,
    rule_id: null,
    records: null,
    cache_records: null,
  };
}
const options = [
  {
    label: "A",
    value: "A",
  },
  {
    label: "AAAA",
    value: "AAAA",
  },
];

const loading = ref(false);
const config_rule = ref<DnsRule>();
const redirect_rule = ref<DNSRedirectRule>();
async function query() {
  if (req.value.domain !== "") {
    loading.value = true;
    try {
      config_rule.value = undefined;
      redirect_rule.value = undefined;
      result.value = await check_domain(req.value);
      if (result.value.rule_id) {
        config_rule.value = await get_dns_rule(result.value.rule_id);
      }
      if (result.value.redirect_id) {
        redirect_rule.value = await get_dns_redirect(result.value.redirect_id);
      }
    } finally {
      loading.value = false;
    }
  } else {
    message.info("请输入待查询域名");
  }
}
const showInner = ref(false);

async function quick_btn(record_type: LandscapeDnsRecordType, domain: string) {
  req.value.domain = domain;
  req.value.record_type = record_type;
  query();
}
</script>

<template>
  <n-drawer
    @after-enter="init_req()"
    @after-leave="init_req()"
    v-model:show="show"
    width="500px"
    placement="right"
    :mask-closable="false"
  >
    <n-drawer-content
      :title="`测试 flow: ${flow_id} 域名查询 (结果不缓存)`"
      closable
    >
      <n-flex style="height: 100%" vertical>
        <n-flex :wrap="false" justify="space-between">
          <n-button
            size="small"
            :loading="loading"
            type="info"
            ghost
            @click="quick_btn('A', 'www.baidu.com')"
          >
            IPv4 Baidu
          </n-button>
          <n-button
            size="small"
            ghost
            :loading="loading"
            type="success"
            @click="quick_btn('AAAA', 'www.baidu.com')"
          >
            IPv6 Baidu
          </n-button>
          <n-button
            size="small"
            :loading="loading"
            type="info"
            ghost
            @click="quick_btn('A', 'test.ustc.edu.cn')"
          >
            IPv4 USTC
          </n-button>
          <n-button
            size="small"
            ghost
            :loading="loading"
            type="success"
            @click="quick_btn('AAAA', 'test6.ustc.edu.cn')"
          >
            IPv6 USTC
          </n-button>
        </n-flex>
        <n-spin :show="loading">
          <n-input-group>
            <n-select
              :style="{ width: '33%' }"
              v-model:value="req.record_type"
              :options="options"
            />
            <n-input
              placeholder="输入域名后, 点击右侧按钮或使用回车"
              @keyup.enter="query"
              v-model:value="req.domain"
            />

            <n-button @click="query">
              <template #icon>
                <n-icon>
                  <SearchLocate />
                </n-icon>
              </template>
            </n-button>
          </n-input-group>
        </n-spin>

        <n-scrollbar>
          <n-flex v-if="config_rule" vertical>
            <DnsRuleCard :rule="config_rule"> </DnsRuleCard>

            <n-divider title-placement="left"> DNS 上游查询结果 </n-divider>
            <n-flex v-if="result.records">
              <n-flex v-for="each in result.records">
                {{ each }}
              </n-flex>
            </n-flex>
            <n-divider title-placement="left"> DNS 内部缓存结果 </n-divider>
            <n-flex v-if="result.cache_records">
              <n-flex v-for="each in result.cache_records">
                {{ each }}
              </n-flex>
            </n-flex>
          </n-flex>

          <n-flex v-if="redirect_rule" vertical>
            <DnsRedirectCard :rule="redirect_rule"></DnsRedirectCard>
            <n-divider title-placement="left"> 域名重定向结果 </n-divider>
            <n-flex v-if="result.records">
              <n-flex v-for="each in result.records">
                {{ each }}
              </n-flex>
            </n-flex>
          </n-flex>
        </n-scrollbar>
      </n-flex>
    </n-drawer-content>
  </n-drawer>
</template>
