<script setup lang="ts">
import { get_all_ipv6pd_status } from "@/api/service_ipv6pd";
import { ServiceStatus } from "@/lib/services";
import type { IPV6RaConfigSource } from "@landscape-router/types/api/schemas";
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";

const show = defineModel<boolean>("show", { required: true });
const source = defineModel<IPV6RaConfigSource>("source");
const { t } = useI18n();

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
        window.$message.error(t("icmp_ra.source_edit.pd_iface_required"));
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
    :title="t('icmp_ra.source_edit.title')"
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
        <n-radio-button
          :key="'static'"
          :value="'static'"
          :label="t('icmp_ra.source_edit.mode_static')"
        />
        <n-radio-button
          :key="'pd'"
          :value="'pd'"
          :label="t('icmp_ra.source_edit.mode_pd')"
        />
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
          :label="t('icmp_ra.source_edit.depend_iface')"
        >
          <n-select
            v-model:value="edit_source.depend_iface"
            filterable
            :placeholder="t('icmp_ra.source_edit.depend_iface_placeholder')"
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
              {{ t("icmp_ra.source_edit.subnet_index") }}
              <template #msg>
                {{ t("icmp_ra.source_edit.subnet_index_desc_1") }} <br />
                {{ t("icmp_ra.source_edit.subnet_index_desc_2") }} <br />
                {{ t("icmp_ra.source_edit.subnet_index_desc_3") }}
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
              {{ t("icmp_ra.source_edit.subnet_prefix_len") }}
              <template #msg>
                {{ t("icmp_ra.source_edit.subnet_prefix_len_desc") }}
              </template>
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
              {{ t("icmp_ra.source_edit.preferred_lifetime") }}
              <template #msg>
                {{ t("icmp_ra.source_edit.preferred_lifetime_desc_1") }}<br />
                {{ t("icmp_ra.source_edit.preferred_lifetime_desc_2") }}
              </template>
            </Notice>
          </template>
          <n-input-number
            style="flex: 1"
            v-model:value="edit_source.ra_preferred_lifetime"
            clearable
          />
        </n-form-item-gi>
        <n-form-item-gi
          span="2 m:2 l:2"
          :label="t('icmp_ra.source_edit.valid_lifetime')"
        >
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
              {{ t("icmp_ra.source_edit.base_prefix") }}
              <template #msg>
                {{ t("icmp_ra.source_edit.base_prefix_desc") }}
              </template>
            </Notice>
          </template>
          <n-flex style="flex: 1" vertical>
            <n-alert type="warning">
              {{ t("icmp_ra.source_edit.base_prefix_desc") }}
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
              {{ t("icmp_ra.source_edit.subnet_index") }}
              <template #msg>
                {{ t("icmp_ra.source_edit.subnet_index_desc_1") }} <br />
                {{ t("icmp_ra.source_edit.subnet_index_desc_2") }} <br />
                {{ t("icmp_ra.source_edit.subnet_index_desc_3") }}
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
              {{ t("icmp_ra.source_edit.subnet_prefix_len") }}
              <template #msg>
                {{ t("icmp_ra.source_edit.subnet_prefix_len_desc") }}
              </template>
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
              {{ t("icmp_ra.source_edit.preferred_lifetime") }}
              <template #msg>
                {{ t("icmp_ra.source_edit.preferred_lifetime_desc_1") }}<br />
                {{ t("icmp_ra.source_edit.preferred_lifetime_desc_2") }}
              </template>
            </Notice>
          </template>
          <n-input-number
            style="flex: 1"
            v-model:value="edit_source.ra_preferred_lifetime"
            clearable
          />
        </n-form-item-gi>
        <n-form-item-gi
          span="2 m:2 l:2"
          :label="t('icmp_ra.source_edit.valid_lifetime')"
        >
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
        <n-button @click="show = false">{{ t("icmp_ra.source_edit.cancel") }}</n-button>
        <n-button @click="commit" type="success">{{ t("icmp_ra.source_edit.confirm") }}</n-button>
      </n-flex>
    </template>
  </n-modal>
</template>
