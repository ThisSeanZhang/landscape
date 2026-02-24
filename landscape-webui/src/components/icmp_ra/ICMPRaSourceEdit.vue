<script setup lang="ts">
import { get_all_ipv6pd_status } from "@/api/service_ipv6pd";
import { ServiceStatus } from "@/lib/services";
import type { IPV6RaConfigSource } from "landscape-types/api/schemas";
import { computed, ref } from "vue";

const show = defineModel<boolean>("show", { required: true });
const source = defineModel<IPV6RaConfigSource>("source");

const edit_source = ref<IPV6RaConfigSource>();

function on_crate(): IPV6RaConfigSource {
  return {
    t: "pd",
    depend_iface: "",
    prefix_len: 64,
    subnet_index: 0,
    ra_preferred_lifetime: 300,
    ra_valid_lifetime: 600,
  };
}

function change_mode(mode: "static" | "pd") {
  console.log(mode == "pd");
  if (mode == "pd") {
    edit_source.value = {
      t: "pd",
      depend_iface: "",
      prefix_len: 64,
      subnet_index: 0,
      ra_preferred_lifetime: 300,
      ra_valid_lifetime: 600,
    };
  } else {
    edit_source.value = {
      t: "static",
      base_prefix: "fd11:2222:3333:4400::",
      sub_prefix_len: 64,
      sub_index: 0,
      ra_preferred_lifetime: 300,
      ra_valid_lifetime: 600,
    };
  }
}

const ipv6_pd_ifaces = ref<Map<string, ServiceStatus>>(new Map());
const loading_search_ipv6pd = ref(false);

const ipv6_pd_options = computed(() => {
  const result = [];
  for (const [key, value] of ipv6_pd_ifaces.value) {
    result.push({ value: key, label: `${key} - ${value.t}` });
  }
  return result;
});

async function search_ipv6_pd() {
  ipv6_pd_ifaces.value = await get_all_ipv6pd_status();
}

async function enter() {
  await search_ipv6_pd();
  if (source.value) {
    edit_source.value = JSON.parse(JSON.stringify(source.value));
  } else {
    edit_source.value = on_crate();
  }
}

const emit = defineEmits(["commit"]);
async function commit() {
  if (edit_source.value) {
    if (edit_source.value.t == "pd") {
      if (edit_source.value.depend_iface.trim() == "") {
        window.$message.error("未选择 PD 网卡");
        return;
      }
    }
    emit("commit", edit_source.value);
    show.value = false;
  }
}
</script>
<template>
  <n-modal
    :auto-focus="false"
    style="width: 600px"
    v-model:show="show"
    class="custom-card"
    preset="card"
    title="前缀来源编辑"
    size="small"
    :bordered="false"
    @after-enter="enter"
  >
    <template #header-extra>
      <n-radio-group
        v-if="edit_source"
        :value="edit_source.t"
        @update:value="change_mode"
        name="prefix-source"
        size="small"
      >
        <n-radio-button :key="'static'" :value="'static'" label="静态前缀" />
        <n-radio-button :key="'pd'" :value="'pd'" label="IPv6 PD" />
      </n-radio-group>
    </template>
    <n-flex v-if="edit_source">
      <n-grid
        v-if="edit_source.t == 'pd'"
        :x-gap="12"
        :y-gap="8"
        cols="4"
        item-responsive
      >
        <n-form-item-gi
          span="4 m:4 l:4"
          label="所关联的网卡 (须对应网卡开启 DHCPv6-PD)"
        >
          <n-select
            v-model:value="edit_source.depend_iface"
            filterable
            placeholder="选择进行前缀申请的网卡"
            :options="ipv6_pd_options"
            :loading="loading_search_ipv6pd"
            clearable
            remote
            @search="search_ipv6_pd"
          />

          <!-- <n-input
              style="flex: 1"
              v-model:value="value.depend_iface"
              clearable
            /> -->
        </n-form-item-gi>

        <n-form-item-gi span="2 m:2 l:2">
          <template #label>
            <Notice>
              子网索引
              <template #msg>
                应用与内网的子网索引 <br />
                由于 NPT 的实现原因 <br />
                子网索引在同一个 LAN 中不可重复
              </template>
            </Notice>
          </template>
          <n-input-number
            style="flex: 1"
            :min="0"
            :max="15"
            v-model:value="edit_source.subnet_index"
            clearable
          />
        </n-form-item-gi>
        <n-form-item-gi span="2 m:2 l:2">
          <template #label>
            <Notice>
              子网前缀长度
              <template #msg> 如遇问题可尝试设置 64 </template>
            </Notice>
          </template>
          <n-input-number
            style="flex: 1"
            :min="0"
            :max="64"
            v-model:value="edit_source.prefix_len"
            clearable
          />
        </n-form-item-gi>

        <n-form-item-gi span="2 m:2 l:2">
          <template #label>
            <Notice>
              IP 首选状态时间 (s)
              <template #msg>
                主机会优先使用在首选时间内的 IP<br />
                相对于超过首选时间但是未超过 有效时间 的 IP
              </template>
            </Notice>
          </template>
          <n-input-number
            style="flex: 1"
            v-model:value="edit_source.ra_preferred_lifetime"
            clearable
          />
        </n-form-item-gi>
        <n-form-item-gi span="2 m:2 l:2" label="IP 有效状态时间 (s)">
          <n-input-number
            style="flex: 1"
            v-model:value="edit_source.ra_valid_lifetime"
            clearable
          />
        </n-form-item-gi>
      </n-grid>
      <n-grid v-else :x-gap="12" :y-gap="8" cols="4" item-responsive>
        <n-form-item-gi span="4 m:4 l:4">
          <template #label>
            <Notice>
              基础前缀定义
              <template #msg>
                注意! 最多只可自定义到 /60, 格式需要保持 ::xxx0, 因为低位 0
                不可省略
              </template>
            </Notice>
          </template>
          <n-flex style="flex: 1" vertical>
            <n-alert type="warning">
              注意! 最多只可自定义到 /60, 格式需要保持 ::xxx0, 因为低位 0
              不可省略
            </n-alert>
            <n-input
              style="flex: 1"
              v-model:value="edit_source.base_prefix"
              clearable
            />
          </n-flex>
        </n-form-item-gi>

        <n-form-item-gi span="2 m:2 l:2">
          <template #label>
            <Notice>
              子网索引
              <template #msg>
                应用与内网的子网索引 <br />
                由于 NPT 的实现原因 <br />
                子网索引在同一个 LAN 中不可重复
              </template>
            </Notice>
          </template>
          <n-input-number
            style="flex: 1"
            :min="0"
            :max="64"
            v-model:value="edit_source.sub_index"
            clearable
          />
        </n-form-item-gi>

        <n-form-item-gi span="2 m:2 l:2">
          <template #label>
            <Notice>
              子网前缀长度
              <template #msg> 如遇问题可尝试设置 64 </template>
            </Notice>
          </template>
          <n-input-number
            style="flex: 1"
            :min="0"
            :max="64"
            v-model:value="edit_source.sub_prefix_len"
            clearable
          />
        </n-form-item-gi>

        <n-form-item-gi span="2 m:2 l:2">
          <template #label>
            <Notice>
              IP 首选状态时间 (s)
              <template #msg>
                主机会优先使用在首选时间内的 IP<br />
                相对于超过首选时间但是未超过 有效时间 的 IP
              </template>
            </Notice>
          </template>
          <n-input-number
            style="flex: 1"
            v-model:value="edit_source.ra_preferred_lifetime"
            clearable
          />
        </n-form-item-gi>
        <n-form-item-gi span="2 m:2 l:2" label="IP 有效状态时间 (s)">
          <n-input-number
            style="flex: 1"
            v-model:value="edit_source.ra_valid_lifetime"
            clearable
          />
        </n-form-item-gi>
      </n-grid>
    </n-flex>

    <template #footer>
      <n-flex justify="space-between">
        <n-button @click="show = false">取消</n-button>
        <n-button @click="commit" type="success">确定</n-button>
      </n-flex>
    </template>
  </n-modal>
</template>
