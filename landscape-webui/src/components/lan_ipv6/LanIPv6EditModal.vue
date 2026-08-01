<script setup lang="ts">
import { computed, ref } from "vue";
import { FormInst, useMessage } from "naive-ui";
import { useI18n } from "vue-i18n";
import { IfaceZoneType } from "@landscape-router/types/api/schemas";
import ConfigModal from "@/components/common/ConfigModal.vue";
import { useIPv6PDStore } from "@/stores/status_ipv6pd";
import {
  get_lan_ipv6_config,
  update_lan_ipv6_config,
} from "@/api/service_lan_ipv6";
import { get_all_ipv6pd_configs } from "@/api/service_ipv6pd";
import type {
  LanIPv6ServiceConfigV2,
  LanPrefixGroupConfig,
  IPv6ServiceMode,
} from "@landscape-router/types/api/schemas";
import DHCPv6ServerCard from "@/components/dhcp_v6/DHCPv6ServerCard.vue";
import PrefixGroupCard from "@/components/lan_ipv6/PrefixGroupCard.vue";
import PrefixGroupEditorModal from "@/components/lan_ipv6/PrefixGroupEditorModal.vue";

const { t } = useI18n({ useScope: "global" });
let ipv6PDStore = useIPv6PDStore();
const message = useMessage();

const show_model = defineModel<boolean>("show", { required: true });
const emit = defineEmits(["refresh"]);
const formRef = ref<FormInst | null>(null);

const iface_info = defineProps<{
  iface_name: string;
  mac?: string;
  zone: IfaceZoneType;
}>();

const service_config = ref<LanIPv6ServiceConfigV2>();
const expectedPdLens = ref<Map<string, number>>(new Map());
const origin_config_json = ref("");

const service_enabled = computed({
  get() {
    return service_config.value?.enable ?? false;
  },
  set(value: boolean) {
    if (service_config.value) {
      service_config.value.enable = value;
    }
  },
});

const config_dirty = computed(
  () =>
    !!service_config.value &&
    origin_config_json.value !== JSON.stringify(service_config.value),
);

function default_config(): LanIPv6ServiceConfigV2 {
  return {
    iface_name: iface_info.iface_name,
    enable: true,
    config: {
      mode: "slaac" as IPv6ServiceMode,
      ad_interval: 300,
      lifetime: 300,
      ra_flag: {
        managed_address_config: false,
        other_config: false,
        home_agent: false,
        prf: 0,
        nd_proxy: false,
        reserved: 0,
      },
      prefix_groups: [],
      dhcpv6: {
        enable: false,
      },
    },
  };
}

const all_groups = computed(
  () => service_config.value?.config.prefix_groups ?? [],
);

function allowed_service_kinds_for_type(): ("ra" | "na" | "pd")[] {
  const mode = service_config.value?.config.mode ?? "slaac";
  if (mode === "slaac") {
    return ["ra"];
  }
  if (mode === "stateful") {
    return ["na", "pd"];
  }
  return ["ra", "na", "pd"];
}

async function on_modal_enter() {
  const pdConfigs = await get_all_ipv6pd_configs().catch(() => []);
  expectedPdLens.value = new Map(
    pdConfigs.map((config) => [
      config.iface_name,
      config.config.expected_pd_len,
    ]),
  );
  try {
    let config = await get_lan_ipv6_config(iface_info.iface_name);
    if (config) {
      service_config.value = config;
    } else {
      service_config.value = default_config();
    }
    if (!service_config.value.config.prefix_groups) {
      service_config.value.config.prefix_groups = [];
    }
    // Always ensure dhcpv6 config is initialized
    if (!service_config.value.config.dhcpv6) {
      service_config.value.config.dhcpv6 = {
        enable: false,
      };
    }
    // Default mode to slaac if not set
    if (!service_config.value.config.mode) {
      service_config.value.config.mode = "slaac" as IPv6ServiceMode;
    }
    if (service_config.value.config.lifetime == null) {
      service_config.value.config.lifetime = 300;
    }
  } catch (e) {
    service_config.value = default_config();
  }

  origin_config_json.value = service_config.value
    ? JSON.stringify(service_config.value)
    : "";
}

function on_mode_change(mode: IPv6ServiceMode) {
  if (!service_config.value) return;
  service_config.value.config.mode = mode;

  const ensure_dhcpv6 = () => {
    if (!service_config.value) return;
    if (!service_config.value.config.dhcpv6) {
      service_config.value.config.dhcpv6 = {
        enable: true,
      };
    } else {
      service_config.value.config.dhcpv6.enable = true;
    }
    if (!service_config.value.config.dhcpv6.ia_na) {
      service_config.value.config.dhcpv6.ia_na = {
        max_prefix_len: 64,
        pool_start: 256,
        preferred_lifetime: 300,
        valid_lifetime: 600,
      };
    }
    if (!service_config.value.config.dhcpv6.ia_pd) {
      service_config.value.config.dhcpv6.ia_pd = {
        delegate_prefix_len: 64,
        preferred_lifetime: 300,
        valid_lifetime: 600,
      };
    }
  };

  // Auto-set flags based on mode
  if (mode === "slaac") {
    service_config.value.config.ra_flag.managed_address_config = false;
    service_config.value.config.ra_flag.other_config = false;
    // Disable DHCPv6
    if (service_config.value.config.dhcpv6) {
      service_config.value.config.dhcpv6.enable = false;
    }
  } else if (mode === "stateful") {
    service_config.value.config.ra_flag.managed_address_config = true;
    service_config.value.config.ra_flag.other_config = true;
    ensure_dhcpv6();
  } else if (mode === "slaac_dhcpv6") {
    service_config.value.config.ra_flag.managed_address_config = true;
    service_config.value.config.ra_flag.other_config = true;
    ensure_dhcpv6();
  }
}

async function save_config() {
  try {
    await formRef.value?.validate();
  } catch (_err) {
    message.warning(t("lan_ipv6.form_validation_failed"));
    return;
  }

  try {
    if (service_config.value) {
      await update_lan_ipv6_config(service_config.value);
      await ipv6PDStore.UPDATE_INFO();
      show_model.value = false;
    }
  } catch (err: any) {
    message.error(err?.message || t("lan_ipv6.form_validation_failed"));
  }
}

const formRules = {};

const show_static_source_add = ref(false);
const show_pd_source_add = ref(false);

function add_group_sources(group: LanPrefixGroupConfig | undefined) {
  if (service_config.value) {
    if (!service_config.value.config.prefix_groups) {
      service_config.value.config.prefix_groups = [];
    }
    if (!group) {
      return;
    }
    service_config.value.config.prefix_groups.unshift(group);
  }
}

function replace_group_sources(
  group_key: string,
  group: LanPrefixGroupConfig | undefined,
) {
  if (!service_config.value?.config.prefix_groups) {
    return;
  }
  const currentGroups = [...service_config.value.config.prefix_groups];
  const index = currentGroups.findIndex(
    (currentGroup) => currentGroup.group_id === group_key,
  );
  if (index === -1) {
    return;
  }
  if (!group) {
    currentGroups.splice(index, 1);
  } else {
    currentGroups.splice(index, 1, group);
  }
  service_config.value.config.prefix_groups = currentGroups;
}
</script>

<template>
  <ConfigModal
    v-model:show="show_model"
    v-model:enabled="service_enabled"
    :mask-closable="!config_dirty"
    :title="t('lan_ipv6.title')"
    :switch-disabled="!service_config"
    width="1200px"
    @after-enter="on_modal_enter"
  >
    <n-form
      v-if="service_config"
      ref="formRef"
      :model="service_config"
      :rules="formRules"
    >
      <!-- Mode selector -->
      <n-card
        style="width: 100%; margin-bottom: 12px"
        size="small"
        :bordered="false"
      >
        <div class="mode-settings-grid">
          <n-form-item :label="t('lan_ipv6.mode')" class="mode-setting">
            <n-radio-group
              :value="service_config.config.mode"
              @update:value="on_mode_change"
              name="ipv6-mode"
            >
              <n-radio-button value="slaac" :label="t('lan_ipv6.mode_slaac')" />
              <n-radio-button
                value="stateful"
                :label="t('lan_ipv6.mode_stateful')"
              />
              <n-radio-button
                value="slaac_dhcpv6"
                :label="t('lan_ipv6.mode_slaac_dhcpv6')"
              />
            </n-radio-group>
          </n-form-item>

          <n-form-item class="lifetime-setting">
            <template #label>
              <Notice>
                {{ t("lan_ipv6.lifetime") }}
                <template #msg>
                  <div>{{ t("lan_ipv6.lifetime_desc") }}</div>
                  <div style="margin-top: 4px">
                    {{ t("lan_ipv6.lifetime_hint") }}
                  </div>
                </template>
              </Notice>
            </template>
            <n-input-number
              v-model:value="service_config.config.lifetime"
              class="lifetime-input"
              :min="60"
              :max="65535"
              :step="60"
            >
              <template #suffix>{{ t("lan_ipv6.seconds") }}</template>
            </n-input-number>
          </n-form-item>
        </div>

        <n-alert
          v-if="service_config.config.mode === 'slaac'"
          type="info"
          :bordered="false"
          style="margin-top: 8px"
        >
          {{ t("lan_ipv6.mode_slaac_desc") }}
        </n-alert>
        <n-alert
          v-else-if="service_config.config.mode === 'stateful'"
          type="info"
          :bordered="false"
          style="margin-top: 8px"
        >
          {{ t("lan_ipv6.mode_stateful_desc") }}
        </n-alert>
        <n-alert
          v-else-if="service_config.config.mode === 'slaac_dhcpv6'"
          type="info"
          :bordered="false"
          style="margin-top: 8px"
        >
          {{ t("lan_ipv6.mode_slaac_dhcpv6_desc") }}
        </n-alert>
      </n-card>

      <n-card
        style="width: 100%; margin-bottom: 12px"
        size="small"
        :title="t('lan_ipv6.prefix_overview')"
        :bordered="false"
      >
        <template #header-extra>
          <n-flex :size="8">
            <n-button size="tiny" @click="show_static_source_add = true">
              {{ t("lan_ipv6.add_static_prefix") }}
            </n-button>
            <n-button
              size="tiny"
              type="primary"
              @click="show_pd_source_add = true"
            >
              {{ t("lan_ipv6.add_pd_prefix") }}
            </n-button>
          </n-flex>
          <PrefixGroupEditorModal
            @commit="add_group_sources"
            v-model:show="show_static_source_add"
            :allowed-service-kinds="allowed_service_kinds_for_type()"
            source-type="static"
            :parent-label="t('lan_ipv6.add_static_prefix')"
            :group="undefined"
            :current-iface-name="service_config.iface_name"
            :current-groups="all_groups"
            :current-mode="service_config.config.mode"
          />
          <PrefixGroupEditorModal
            @commit="add_group_sources"
            v-model:show="show_pd_source_add"
            :allowed-service-kinds="allowed_service_kinds_for_type()"
            source-type="pd"
            :parent-label="t('lan_ipv6.add_pd_prefix')"
            :group="undefined"
            :current-iface-name="service_config.iface_name"
            :current-groups="all_groups"
            :current-mode="service_config.config.mode"
          />
        </template>

        <n-flex v-if="all_groups.length > 0" vertical>
          <PrefixGroupCard
            v-for="group in all_groups"
            :key="group.group_id"
            :group="group"
            :allowed-service-kinds="allowed_service_kinds_for_type()"
            :iface-name="service_config.iface_name"
            :current-groups="all_groups"
            :current-mode="service_config.config.mode"
            :expected-pd-lens="expectedPdLens"
            @commit-group="replace_group_sources"
          />
        </n-flex>

        <n-empty v-else :description="t('lan_ipv6.no_prefix')" />
      </n-card>

      <!-- Bottom config area -->
      <n-flex :gap="12" align="stretch">
        <!-- RA config -->
        <n-card
          style="flex: 1; min-width: 0"
          size="small"
          :title="t('lan_ipv6.ra_config')"
          :bordered="false"
        >
          <n-grid :x-gap="12" :y-gap="8" cols="2" item-responsive>
            <!-- M/O flags: show read-only for stateful/slaac_dhcpv6, editable for slaac -->
            <template v-if="service_config.config.mode === 'slaac'">
              <n-form-item-gi span="2">
                <template #label>
                  <Notice>
                    {{ t("lan_ipv6.m_flag") }}
                    <template #msg>
                      {{ t("lan_ipv6.m_flag_desc") }}
                    </template>
                  </Notice>
                </template>
                <n-switch
                  v-model:value="
                    service_config.config.ra_flag.managed_address_config
                  "
                />
              </n-form-item-gi>
              <n-form-item-gi span="2">
                <template #label>
                  <Notice>
                    {{ t("lan_ipv6.o_flag") }}
                    <template #msg>
                      {{ t("lan_ipv6.o_flag_desc") }}
                    </template>
                  </Notice>
                </template>
                <n-switch
                  v-model:value="service_config.config.ra_flag.other_config"
                />
              </n-form-item-gi>
            </template>
            <template v-else>
              <n-form-item-gi span="2">
                <template #label>
                  <Notice>
                    {{ t("lan_ipv6.ra_flags_auto") }}
                    <template #msg>
                      {{ t("lan_ipv6.ra_flags_auto_desc") }}
                    </template>
                  </Notice>
                </template>
                <n-tag :bordered="false" type="info"> M=1, O=1 </n-tag>
              </n-form-item-gi>
            </template>

            <n-form-item-gi span="2" :label="t('lan_ipv6.route_priority')">
              <n-radio-group
                v-model:value="service_config.config.ra_flag.prf"
                name="ra_flag"
              >
                <n-radio-button
                  :value="3"
                  :label="t('lan_ipv6.priority_low')"
                />
                <n-radio-button
                  :value="0"
                  :label="t('lan_ipv6.priority_medium')"
                />
                <n-radio-button
                  :value="1"
                  :label="t('lan_ipv6.priority_high')"
                />
              </n-radio-group>
            </n-form-item-gi>
          </n-grid>
        </n-card>

        <!-- DHCPv6 Server Config (only for stateful and slaac_dhcpv6) -->
        <DHCPv6ServerCard
          v-if="
            service_config.config.mode === 'stateful' ||
            service_config.config.mode === 'slaac_dhcpv6'
          "
          v-model:service-config="service_config"
        />
      </n-flex>
    </n-form>
    <template #footer>
      <n-flex justify="end">
        <n-button round type="primary" @click="save_config">
          {{ t("lan_ipv6.update") }}
        </n-button>
      </n-flex>
    </template>
  </ConfigModal>
</template>

<style scoped>
.mode-settings-grid {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(280px, 360px);
  gap: 16px 24px;
  align-items: start;
}

.mode-setting,
.lifetime-setting {
  min-width: 0;
  margin-bottom: 0;
}

.lifetime-input {
  width: 100%;
}

@media (max-width: 900px) {
  .mode-settings-grid {
    grid-template-columns: minmax(0, 1fr);
    gap: 12px;
  }
}
</style>
