<script setup lang="ts">
import { ref } from "vue";
import { FormInst, useMessage } from "naive-ui";
import { ZoneType } from "@/lib/service_ipconfig";
import { useIPv6PDStore } from "@/stores/status_ipv6pd";
import {
  get_iface_icmpv6ra_config,
  update_icmpv6ra_config,
} from "@/api/service_icmpv6ra";
import type {
  IPV6RaConfigSource,
  IPv6RaPdConfig,
  IPV6RAServiceConfig,
  IPv6RaStaticConfig,
} from "@landscape-router/types/api/schemas";
import { indexMap } from "seemly";
import { useI18n } from "vue-i18n";

let ipv6PDStore = useIPv6PDStore();
const message = useMessage();
const { t } = useI18n();

const show_model = defineModel<boolean>("show", { required: true });
const emit = defineEmits(["refresh"]);
const formRef = ref<FormInst | null>(null);

const iface_info = defineProps<{
  iface_name: string;
  mac?: string;
  zone: ZoneType;
}>();

const service_config = ref<IPV6RAServiceConfig>();

async function on_modal_enter() {
  try {
    let config = await get_iface_icmpv6ra_config(iface_info.iface_name);
    console.log(config);
    // iface_service_type.value = config.t;
    if (config) {
      service_config.value = config;
    } else {
    }
  } catch (e) {
    service_config.value = {
      iface_name: iface_info.iface_name,
      enable: true,
      config: {
        ad_interval: 300,
        ra_flag: {
          managed_address_config: true,
          other_config: true,
          home_agent: false,
          prf: 0,
          nd_proxy: false,
          reserved: 0,
        },
        source: [],
      },
    };
  }
}

async function save_config() {
  try {
    await formRef.value?.validate();
    if (service_config.value) {
      if (!validate(service_config.value.config.source)) {
        return;
      }
      let config = await update_icmpv6ra_config(service_config.value);
      await ipv6PDStore.UPDATE_INFO();
      show_model.value = false;
    }
  } catch (err) {
    message.warning(t("icmp_ra.edit_modal.form_invalid"));
  }
}

const formRules = {
  config: {
    depend_iface: {
      required: true,
      message: t("icmp_ra.source_edit.depend_iface_placeholder"),
      trigger: ["blur", "change"],
    },
  },
};

const show_source_edit = ref(false);
function add_source(source: IPV6RaConfigSource) {
  service_config.value?.config.source.unshift(source);
}

function replace_source(source: IPV6RaConfigSource, index: number) {
  if (service_config.value) {
    service_config.value.config.source[index] = source;
  }
}

function delete_source(index: number) {
  if (service_config.value) {
    service_config.value.config.source.splice(index, 1);
  }
}

function validate(source: IPV6RaConfigSource[]): boolean {
  const basePrefixes = new Set<string>();
  const dependIfaces = new Set<string>();
  const subnetIndices = new Set<number>();

  for (const src of source) {
    switch (src.t) {
      case "static": {
        const s = src as IPv6RaStaticConfig;
        if (basePrefixes.has(s.base_prefix)) {
          window.$message.warning(
            t("icmp_ra.edit_modal.duplicate_static_prefix", { prefix: s.base_prefix }),
          );
          return false;
        }
        basePrefixes.add(s.base_prefix);

        if (subnetIndices.has(s.sub_index)) {
          window.$message.warning(
            t("icmp_ra.edit_modal.duplicate_subnet_index", { index: s.sub_index }),
          );
          return false;
        }
        subnetIndices.add(s.sub_index);
        break;
      }
      case "pd": {
        const p = src as IPv6RaPdConfig;
        if (dependIfaces.has(p.depend_iface)) {
          window.$message.warning(
            t("icmp_ra.edit_modal.duplicate_iface", { iface: p.depend_iface }),
          );
          return false;
        }
        dependIfaces.add(p.depend_iface);

        if (subnetIndices.has(p.subnet_index)) {
          window.$message.warning(
            t("icmp_ra.edit_modal.duplicate_subnet_index", { index: p.subnet_index }),
          );
          return false;
        }
        subnetIndices.add(p.subnet_index);
        break;
      }
    }
  }

  return true;
}
</script>

<template>
  <n-modal
    :auto-focus="false"
    v-model:show="show_model"
    @after-enter="on_modal_enter"
  >
    <n-card
      style="width: 600px"
      :title="t('icmp_ra.edit_modal.title')"
      :bordered="false"
      size="small"
      role="dialog"
      aria-modal="true"
      closable
      @close="show_model = false"
    >
      <!-- {{ service_config }} -->
      <n-form
        v-if="service_config"
        ref="formRef"
        :model="service_config"
        :rules="formRules"
      >
        <n-grid :x-gap="12" :y-gap="8" cols="4" item-responsive>
          <n-form-item-gi span="2 m:2 l:2" :label="t('icmp_ra.edit_modal.enable')">
            <n-switch v-model:value="service_config.enable">
              <template #checked> {{ t("icmp_ra.edit_modal.enabled_yes") }} </template>
              <template #unchecked> {{ t("icmp_ra.edit_modal.enabled_no") }} </template>
            </n-switch>
          </n-form-item-gi>

          <n-form-item-gi span="2 m:2 l:2">
            <template #label>
              <Notice>
                {{ t("icmp_ra.edit_modal.ad_interval") }}
                <template #msg>
                  {{ t("icmp_ra.edit_modal.ad_interval_desc_1") }} <br />
                  {{ t("icmp_ra.edit_modal.ad_interval_desc_2") }}<br />
                  {{ t("icmp_ra.edit_modal.ad_interval_desc_3") }}
                </template>
              </Notice>
            </template>
            <n-input-number
              style="flex: 1"
              v-model:value="service_config.config.ad_interval"
              clearable
            />
          </n-form-item-gi>

          <n-form-item-gi span="4 m:4 l:4" label="">
            <template #label>
              <n-flex align="center">
                <n-flex>{{ t("icmp_ra.edit_modal.prefix_config") }}</n-flex>
                <n-flex>
                  <!-- 不确定为什么点击 label 会触发第一个按钮, 所以放置一个不可见的按钮 -->
                  <button
                    style="
                      width: 0;
                      height: 0;
                      overflow: hidden;
                      opacity: 0;
                      position: absolute;
                    "
                  ></button>

                  <n-button
                    :focusable="false"
                    size="tiny"
                    @click="show_source_edit = true"
                  >
                    {{ t("icmp_ra.edit_modal.add") }}
                  </n-button>
                  <ICMPRaSourceEdit
                    @commit="add_source"
                    v-model:show="show_source_edit"
                  ></ICMPRaSourceEdit>
                </n-flex>
              </n-flex>
            </template>
            <n-scrollbar style="max-height: 160px">
              <n-flex>
                <ICMPRaSourceExhibit
                  v-for="(each, index) in service_config.config.source"
                  :source="each"
                  @commit="(e: any) => replace_source(e, index)"
                  @delete="delete_source(index)"
                >
                </ICMPRaSourceExhibit>
              </n-flex>
            </n-scrollbar>
            <!-- {{ service_config.config.source }} -->
          </n-form-item-gi>

          <!-- flag 部分 -->
          <!-- <n-form-item-gi span="2 m:2" label="使用 DHCPv6 获取 IPv6 地址">
            <n-switch
              v-model:value="
                service_config.config.ra_flag.managed_address_config
              "
            />
          </n-form-item-gi>
          <n-form-item-gi span="2 m:2" label="使用 DHCPv6 获取 其他信息">
            <n-switch
              v-model:value="service_config.config.ra_flag.other_config"
            />
          </n-form-item-gi>
          <n-form-item-gi span="2 m:2" label="移动 IPv6 归属代理">
            <n-switch
              v-model:value="service_config.config.ra_flag.home_agent"
            />
          </n-form-item-gi>

          <n-form-item-gi span="2 m:2" label="邻居发现代理">
            <n-switch v-model:value="service_config.config.ra_flag.nd_proxy" />
          </n-form-item-gi> -->

          <n-form-item-gi
            span="4 m:4"
            :label="t('icmp_ra.edit_modal.default_route_priority')"
          >
            <n-radio-group
              v-model:value="service_config.config.ra_flag.prf"
              name="ra_flag"
            >
              <n-radio-button :value="3" :label="t('icmp_ra.edit_modal.priority_low')" />
              <n-radio-button
                :value="0"
                :label="t('icmp_ra.edit_modal.priority_medium')"
              />
              <n-radio-button :value="1" :label="t('icmp_ra.edit_modal.priority_high')" />
            </n-radio-group>
          </n-form-item-gi>
        </n-grid>
      </n-form>
      <template #footer>
        <n-flex justify="end">
          <n-button round type="primary" @click="save_config">
            {{ t("icmp_ra.edit_modal.update") }}
          </n-button>
        </n-flex>
      </template>
    </n-card>
  </n-modal>
</template>
