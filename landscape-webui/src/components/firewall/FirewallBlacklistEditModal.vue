<script setup lang="ts">
import { computed, ref } from "vue";
import { useMessage } from "naive-ui";
import { ChangeCatalog, WarningAlt } from "@vicons/carbon";

import IpEdit from "@/components/IpEdit.vue";
import GeoIpKeySelect from "@/components/geo/ip/GeoIpKeySelect.vue";

import {
  push_firewall_blacklist,
  get_firewall_blacklist,
} from "@/api/firewall_blacklist";
import type {
  FirewallBlacklistConfig,
  FirewallBlacklistSource,
} from "@landscape-router/types/api/schemas";

interface Props {
  id: string | null;
}

const props = defineProps<Props>();

const message = useMessage();
const emit = defineEmits(["refresh"]);
const show = defineModel<boolean>("show", { required: true });

const config = ref<FirewallBlacklistConfig>();
const origin_json = ref("");
const commit_spin = ref(false);

const isModified = computed(() => {
  return origin_json.value !== JSON.stringify(config.value);
});

async function enter() {
  if (props.id !== null) {
    config.value = await get_firewall_blacklist(props.id);
  } else {
    config.value = {
      enable: true,
      source: [],
      remark: "",
      update_at: Date.now(),
    };
  }
  origin_json.value = JSON.stringify(config.value);
}

function onCreate(): FirewallBlacklistSource {
  return { t: "config", ip: "0.0.0.0", prefix: 32 };
}

function changeCurrentSourceType(
  value: FirewallBlacklistSource,
  index: number,
) {
  if (config.value) {
    if (value.t === "config") {
      config.value.source[index] = {
        t: "geo_key",
        name: "",
        key: "",
        inverse: false,
        attribute_key: null,
      };
    } else {
      config.value.source[index] = {
        t: "config",
        ip: "0.0.0.0",
        prefix: 32,
      };
    }
  }
}

function validateSources(): boolean {
  if (!config.value) return false;
  for (let i = 0; i < config.value.source.length; i++) {
    const s = config.value.source[i];
    if (s.t === "geo_key" && (!s.key || !s.name)) {
      message.warning(`第 ${i + 1} 条来源: GeoIP Key 不能为空`);
      return false;
    }
    if (s.t === "config" && !s.ip) {
      message.warning(`第 ${i + 1} 条来源: IP 地址不能为空`);
      return false;
    }
  }
  return true;
}

async function saveConfig() {
  if (config.value) {
    if (!validateSources()) return;
    try {
      commit_spin.value = true;
      await push_firewall_blacklist(config.value);
      show.value = false;
    } catch (e: any) {
      message.error(`${e.response?.data || e.message}`);
    } finally {
      commit_spin.value = false;
    }
    emit("refresh");
  }
}
</script>

<template>
  <n-modal
    v-model:show="show"
    style="width: 700px"
    class="custom-card"
    preset="card"
    title="防火墙黑名单编辑"
    @after-enter="enter"
    :bordered="false"
  >
    <n-form v-if="config" style="flex: 1" :model="config">
      <n-grid :cols="5">
        <n-form-item-gi label="启用" :span="2">
          <n-switch v-model:value="config.enable">
            <template #checked> 启用 </template>
            <template #unchecked> 禁用 </template>
          </n-switch>
        </n-form-item-gi>
      </n-grid>
      <n-form-item label="备注">
        <n-input v-model:value="config.remark" type="text" />
      </n-form-item>
      <n-form-item label="黑名单来源">
        <n-dynamic-input v-model:value="config.source" :on-create="onCreate">
          <template #create-button-default> 增加一条来源 </template>
          <template #default="{ value, index }">
            <n-flex style="flex: 1" :wrap="false">
              <n-button @click="changeCurrentSourceType(value, index)">
                <n-icon>
                  <ChangeCatalog />
                </n-icon>
              </n-button>
              <GeoIpKeySelect
                v-model:geo_key="value.key"
                v-model:geo_name="value.name"
                v-if="value.t === 'geo_key'"
              />
              <n-flex v-else style="flex: 1" align="center" :wrap="false">
                <IpEdit v-model:ip="value.ip" v-model:mask="value.prefix" />
                <n-tooltip
                  v-if="
                    (value.ip === '0.0.0.0' || value.ip === '::') &&
                    value.prefix === 0
                  "
                >
                  <template #trigger>
                    <n-icon color="#d03050" :size="20">
                      <WarningAlt />
                    </n-icon>
                  </template>
                  将会阻止所有 IP 的访问
                </n-tooltip>
              </n-flex>
            </n-flex>
          </template>
        </n-dynamic-input>
      </n-form-item>
    </n-form>
    <template #footer>
      <n-flex justify="space-between">
        <n-button @click="show = false">取消</n-button>
        <n-button
          :loading="commit_spin"
          @click="saveConfig"
          :disabled="!isModified"
        >
          保存
        </n-button>
      </n-flex>
    </template>
  </n-modal>
</template>
