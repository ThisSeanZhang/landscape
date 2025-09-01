<script setup lang="ts">
import { ref } from "vue";
import { useMessage } from "naive-ui";
import { SearchLocate } from "@vicons/carbon";
import { CheckDnsReq, CheckDnsResult } from "@/rust_bindings/dns";
import { check_domain } from "@/api/dns_service";
import { LandscapeDnsRecordType } from "@/rust_bindings/common/dns_record_type";
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
const result = ref<CheckDnsResult>({
  config: undefined,
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
    config: undefined,
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
async function query() {
  if (req.value.domain !== "") {
    loading.value = true;
    try {
      result.value = await check_domain(req.value);
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
      :title="`测试 flow: ${flow_id} 域名查询 (结果不会被缓存)`"
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
          <n-flex vertical>
            <n-descriptions
              v-if="result.config"
              bordered
              title="匹配配置"
              label-placement="top"
              :column="3"
            >
              <n-descriptions-item label="名称">
                {{ result.config.name }}
              </n-descriptions-item>
              <n-descriptions-item label="启用">
                <n-tag
                  :bordered="false"
                  :type="result.config.enable ? 'success' : ''"
                >
                  {{ result.config.enable }}
                </n-tag>
              </n-descriptions-item>
              <n-descriptions-item label="流量标记">
                {{ result.config.mark }}
              </n-descriptions-item>
              <n-descriptions-item label="DNS 处理方式" :span="2">
                {{ result.config.resolve_mode }}
              </n-descriptions-item>

              <n-descriptions-item label="匹配规则">
                <n-button
                  v-if="result.config.source.length > 0"
                  @click="showInner = true"
                >
                  详情
                </n-button>
                <span v-else>无内容</span>
              </n-descriptions-item>
            </n-descriptions>
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
        </n-scrollbar>
      </n-flex>
    </n-drawer-content>

    <n-drawer :mask-closable="false" v-model:show="showInner" width="50%">
      <n-drawer-content title="详情" closable>
        <n-flex v-if="result.config" vertical>
          <n-flex v-for="each in result.config.source" :wrap="false">
            <span>{{ each.match_type }}</span>
            <n-flex> {{ each.value }} </n-flex>
          </n-flex>
        </n-flex>
      </n-drawer-content>
    </n-drawer>
  </n-drawer>
</template>
