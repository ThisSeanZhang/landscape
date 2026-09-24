<script setup lang="ts">
import IpEdit from "@/components/IpEdit.vue";
import PortRange from "@/components/PortRange.vue";
import {
  delete_wan_link,
  get_wan_link,
  update_wan_link_config,
} from "@/api/wan_links";
import { new_ifaces } from "@/api/iface";
import type {
  PortRange as PortRangeModel,
  WanLinkConfig,
  WanLinkKindConfig,
  WanV4Model,
} from "@landscape-router/types/api/schemas";
import { formatMacAddress, generateValidMAC } from "@/lib/util";
import { useFrontEndStore } from "@/stores/front_end_config";
import { useWanLinkStatusStore } from "@/stores/status_wan_link";
import { useWanLinkStore, type WanLinkKind } from "@/stores/wan_link";
import { useI18n } from "vue-i18n";
import { computed, ref } from "vue";
import { isIPv4 } from "is-ip";

const PPP_IFACE_NAME_PATTERN = /^[A-Za-z0-9_-]{1,15}$/;
const DEFAULT_NAT_RANGE = (): PortRangeModel => ({ start: 32768, end: 65535 });
const NOTHING_MODEL: WanV4Model = { t: "nothing" };
const IPCP_MODEL = (): WanV4Model => ({ t: "ipcp", default_router: false });

const pluginOptions = [
  { label: "rp-pppoe.so", value: "rp_pppoe" },
  { label: "pppoe.so", value: "pppoe" },
];

const props = withDefaults(
  defineProps<{
    attach_iface_name: string;
    attach_mac?: string | null;
    origin?: WanLinkConfig | undefined;
    initial_kind?: WanLinkKind;
  }>(),
  {
    attach_mac: null,
    origin: undefined,
    initial_kind: "ethernet",
  },
);

const emit = defineEmits(["refresh"]);
const { t } = useI18n();
const frontEndStore = useFrontEndStore();
const wanLinkStore = useWanLinkStore();
const wanLinkStatusStore = useWanLinkStatusStore();

const show_model = defineModel<boolean>("show", { required: true });

const is_editing = computed(() => props.origin !== undefined);
const existing_ifaces = ref<string[]>([]);
const initial_snapshot = ref("");

const config = ref<WanLinkConfig>(default_config());

function is_ppp_kind(kind: WanLinkKind) {
  return kind === "pppoe_native" || kind === "pppd";
}

function gen_ppp_name() {
  const date_str = (new Date().getTime() % (60 * 60 * 24)).toString(36);
  return `ppp-${props.attach_iface_name}-${date_str}`.substring(0, 15);
}

function default_kind_config(kind: WanLinkKind): WanLinkKindConfig {
  switch (kind) {
    case "pppoe_native":
      return {
        t: "pppoe_native",
        username: "",
        password: "",
        requested_mru: 1492,
        ac_name: null,
        lcp_echo_interval: 20,
        redial_backoff_base_secs: 300,
      };
    case "pppd":
      return {
        t: "pppd",
        ppp_iface_name: gen_ppp_name(),
        peer_id: "",
        password: "",
        ac: null,
        plugin: "rp_pppoe",
      };
    default:
      return { t: "ethernet" };
  }
}

function default_pd() {
  return {
    enable: false,
    mac: props.attach_mac ?? generateValidMAC(),
    expected_pd_len: 60,
  };
}

function default_config(): WanLinkConfig {
  return {
    attach_iface_name: props.attach_iface_name,
    name: "",
    kind: default_kind_config(props.initial_kind),
    v4: is_ppp_kind(props.initial_kind)
      ? { enable: true, model: IPCP_MODEL() }
      : { enable: false, model: NOTHING_MODEL },
    pd: default_pd(),
    nat: { enable: false },
    firewall: { enable: false },
    mss: { enable: false, clamp_size: null },
  };
}

function normalize(origin: WanLinkConfig): WanLinkConfig {
  const fallback = default_config();
  const normalized = {
    ...fallback,
    ...JSON.parse(JSON.stringify(origin)),
    kind: origin.kind ?? fallback.kind,
    v4: origin.v4 ?? fallback.v4,
    pd: origin.pd ?? fallback.pd,
    nat: origin.nat ?? fallback.nat,
    firewall: origin.firewall ?? fallback.firewall,
    mss: origin.mss ?? fallback.mss,
  };
  // PPP 的 v4 只允许 Ipcp（启用）或 Nothing（PD-only）；异常数据回退。
  // enable 是后端的暂停开关：false 保留 Ipcp 配置、会话不拨号（PD 除外）。
  if (normalized.kind !== undefined && is_ppp_kind(normalized.kind.t)) {
    const model_t = normalized.v4?.model?.t;
    if (model_t !== "ipcp" && model_t !== "nothing") {
      normalized.v4 = { enable: true, model: IPCP_MODEL() };
    }
  }
  return normalized;
}

async function load_existing_ifaces() {
  try {
    const iface_infos = (await new_ifaces()) as unknown as {
      managed: Array<{ config: { name: string } }>;
      unmanaged: Array<{ status: { name: string } }>;
    };
    existing_ifaces.value = [
      ...iface_infos.managed.map((iface) => iface.config.name),
      ...iface_infos.unmanaged.map((iface) => iface.status.name),
    ];
  } catch {
    existing_ifaces.value = [];
  }
}

async function on_modal_enter() {
  config.value = props.origin ? normalize(props.origin) : default_config();
  initial_snapshot.value = JSON.stringify(config.value);

  const origin_id = props.origin?.id;
  if (origin_id === undefined) {
    if (config.value.kind?.t === "pppd") {
      await load_existing_ifaces();
    }
    return;
  }

  // 每次打开编辑都从后端拉最新配置回显；期间用户已改动时不覆盖。
  try {
    const fresh = await get_wan_link(origin_id);
    if (fresh && !is_modified.value) {
      config.value = normalize(fresh);
      initial_snapshot.value = JSON.stringify(config.value);
    }
  } catch (e) {
    console.error("Failed to refresh wan link config:", e);
  } finally {
    if (config.value.kind?.t === "pppd") {
      await load_existing_ifaces();
    }
  }
}

const is_modified = computed(
  () => JSON.stringify(config.value) !== initial_snapshot.value,
);

const kind_config = computed<WanLinkKindConfig>(
  () => config.value.kind ?? { t: "ethernet" },
);

const kind_options = computed(() => [
  { label: t("wan_link.kind_ethernet"), value: "ethernet" },
  { label: t("wan_link.kind_pppoe_native"), value: "pppoe_native" },
  { label: t("wan_link.kind_pppd"), value: "pppd" },
]);

const is_ppp = computed(() => is_ppp_kind(kind_config.value.t));

const session_tab_label = computed(() =>
  kind_config.value.t === "pppd"
    ? t("wan_link.tab_pppd")
    : kind_config.value.t === "pppoe_native"
      ? t("wan_link.tab_pppoe_native")
      : t("wan_link.tab_v4"),
);

const v4 = computed(
  () => config.value.v4 ?? { enable: false, model: NOTHING_MODEL },
);
const v4_model = computed<WanV4Model>(() => v4.value.model ?? NOTHING_MODEL);
const pd = computed(() => config.value.pd ?? default_pd());
const nat = computed(() => config.value.nat ?? { enable: false });
const firewall = computed(() => config.value.firewall ?? { enable: false });
const mss = computed(
  () => config.value.mss ?? { enable: false, clamp_size: null },
);

/** pppd 口名仅在编辑一条原本就是 pppd 且口名未变的链路时锁定。 */
const ppp_iface_locked = computed(() => {
  const origin_kind = props.origin?.kind;
  if (kind_config.value.t !== "pppd" || origin_kind?.t !== "pppd") {
    return false;
  }
  return kind_config.value.ppp_iface_name === origin_kind.ppp_iface_name;
});

/** The pppd iface name must be globally unique: it must not collide with a
 * system interface or another link's ppp name (on any attach iface). */
const ppp_iface_name_conflict = computed<string | undefined>(() => {
  if (kind_config.value.t !== "pppd") {
    return undefined;
  }
  const ppp_iface_name = kind_config.value.ppp_iface_name;
  if (!ppp_iface_name || !PPP_IFACE_NAME_PATTERN.test(ppp_iface_name)) {
    return undefined;
  }
  const origin_kind = props.origin?.kind;
  const origin_ppp_iface =
    origin_kind?.t === "pppd" ? origin_kind.ppp_iface_name : undefined;
  if (
    ppp_iface_name !== origin_ppp_iface &&
    existing_ifaces.value.includes(ppp_iface_name)
  ) {
    return t("wan_link.validation.ppp_iface_conflict");
  }
  const used_by_other = wanLinkStore.links.some((link) => {
    if (link.id === config.value.id) return false;
    if (link.kind?.t !== "pppd") return false;
    return link.kind.ppp_iface_name === ppp_iface_name;
  });
  return used_by_other
    ? t("wan_link.validation.ppp_iface_conflict")
    : undefined;
});

/** 切换类型：kind 字段整体重置，并复位不兼容的 v4 模型与 MSS auto。 */
function on_kind_change(value: WanLinkKind) {
  config.value.kind = default_kind_config(value);

  if (is_ppp_kind(value)) {
    if (v4_model.value.t !== "ipcp") {
      v4.value.enable = true;
      v4.value.model = IPCP_MODEL();
    }
  } else {
    if (v4_model.value.t === "ipcp") {
      v4.value.enable = false;
      v4.value.model = NOTHING_MODEL;
    }
    if (mss.value.clamp_size == null) {
      mss.value.clamp_size = 1492;
    }
  }
}

const v4_model_options = computed(() => [
  { label: t("wan_link.v4_mode_static"), value: "static" },
  { label: t("wan_link.v4_mode_dhcp"), value: "dhcp_client" },
]);

function select_v4_model(value: string) {
  switch (value) {
    case "static":
      v4.value.model = {
        t: "static",
        ipv4: null,
        ipv4_mask: 24,
        ipv6: null,
        default_router: false,
        default_router_ip: null,
      };
      break;
    case "dhcp_client":
      v4.value.model = {
        t: "dhcp_client",
        hostname: null,
        default_router: false,
        custome_opts: [],
      };
      break;
    default:
      v4.value.model = NOTHING_MODEL;
  }
}

function on_v4_enable(value: boolean) {
  v4.value.enable = value;
  if (value && v4_model.value.t === "nothing") {
    select_v4_model("dhcp_client");
  }
}

function on_ipcp_default_route(value: boolean) {
  if (v4_model.value.t === "ipcp") {
    v4_model.value.default_router = value;
  }
}

/** PPP 会话开关：v4.enable 暂停/恢复拨号（model 保留为 Ipcp）。 */
const ppp_v4_enabled = computed(
  () => is_ppp.value && v4.value.enable && v4_model.value.t === "ipcp",
);

function on_ppp_enable(value: boolean) {
  v4.value.enable = value;
  if (value && v4_model.value.t !== "ipcp") {
    v4.value.model = IPCP_MODEL();
  }
}

const static_mask = computed<number | undefined>({
  get: () =>
    v4_model.value.t === "static"
      ? (v4_model.value.ipv4_mask ?? undefined)
      : undefined,
  set: (value) => {
    if (v4_model.value.t === "static") {
      v4_model.value.ipv4_mask = value;
    }
  },
});

const nat_tcp_range = computed({
  get: () => nat.value.tcp_range ?? DEFAULT_NAT_RANGE(),
  set: (value: PortRangeModel) => (nat.value.tcp_range = { ...value }),
});
const nat_udp_range = computed({
  get: () => nat.value.udp_range ?? DEFAULT_NAT_RANGE(),
  set: (value: PortRangeModel) => (nat.value.udp_range = { ...value }),
});
const nat_icmp_range = computed({
  get: () => nat.value.icmp_in_range ?? DEFAULT_NAT_RANGE(),
  set: (value: PortRangeModel) => (nat.value.icmp_in_range = { ...value }),
});

function on_nat_enable(value: boolean) {
  nat.value.enable = value;
  if (value) {
    nat.value.tcp_range = nat.value.tcp_range ?? DEFAULT_NAT_RANGE();
    nat.value.udp_range = nat.value.udp_range ?? DEFAULT_NAT_RANGE();
    nat.value.icmp_in_range = nat.value.icmp_in_range ?? DEFAULT_NAT_RANGE();
  }
}

const mss_auto = computed(() => mss.value.clamp_size == null);

function set_mss_auto(value: boolean) {
  mss.value.clamp_size = value ? null : 1492;
}

const link_active = computed(
  () => (v4.value.enable && v4_model.value.t !== "nothing") || pd.value.enable,
);

function validate(): string | undefined {
  // Link count / kind exclusivity is not enforced here; the backend's
  // check_link_cardinality is the authority. The pppd iface name conflict is
  // checked live as the user types (ppp_iface_name_conflict).

  if (kind_config.value.t === "pppoe_native") {
    if (!kind_config.value.username || !kind_config.value.password) {
      return t("wan_link.validation.username_password_required");
    }
  } else if (kind_config.value.t === "pppd") {
    if (
      !kind_config.value.ppp_iface_name ||
      !PPP_IFACE_NAME_PATTERN.test(kind_config.value.ppp_iface_name)
    ) {
      return t("wan_link.validation.ppp_iface_invalid");
    }
    if (kind_config.value.ppp_iface_name === props.attach_iface_name) {
      return t("wan_link.validation.ppp_iface_same_as_attach");
    }
    if (ppp_iface_name_conflict.value) {
      return ppp_iface_name_conflict.value;
    }
    if (!kind_config.value.peer_id || !kind_config.value.password) {
      return t("wan_link.validation.username_password_required");
    }
  }

  if (v4.value.enable && v4_model.value.t === "static") {
    const model = v4_model.value;
    if (model.t !== "static") return undefined;
    if (model.ipv4 && !isIPv4(model.ipv4)) {
      return t("wan_link.validation.ipv4_invalid");
    }
    if (model.default_router_ip && !isIPv4(model.default_router_ip)) {
      return t("wan_link.validation.ipv4_invalid");
    }
    if ((model.ipv4_mask ?? 24) > 32) {
      return t("wan_link.validation.mask_invalid");
    }
  }

  const pd_len = pd.value.expected_pd_len ?? 60;
  if (pd.value.enable && (pd_len < 56 || pd_len > 64)) {
    return t("wan_link.validation.pd_len_invalid");
  }

  if (mss.value.enable) {
    const clamp = mss.value.clamp_size;
    if (clamp == null && !is_ppp.value) {
      return t("wan_link.validation.mss_auto_requires_ppp");
    }
    if (clamp != null && (clamp < 536 || clamp > 1500)) {
      return t("wan_link.validation.mss_range");
    }
  }

  return undefined;
}

async function save_config() {
  if (!is_modified.value) {
    show_model.value = false;
    return;
  }

  const error = validate();
  if (error) {
    window.$message.error(error);
    return;
  }

  try {
    const payload: WanLinkConfig = {
      ...config.value,
      name: config.value.name?.trim() || "",
    };
    await update_wan_link_config(payload);
    await Promise.all([
      wanLinkStore.refresh(),
      wanLinkStatusStore.UPDATE_INFO(),
    ]);
    show_model.value = false;
    emit("refresh");
  } catch (e) {
    console.error("Failed to save wan link:", e);
  }
}

async function remove_config() {
  if (config.value.id === undefined) {
    return;
  }
  await delete_wan_link(config.value.id);
  await Promise.all([wanLinkStore.refresh(), wanLinkStatusStore.UPDATE_INFO()]);
  show_model.value = false;
  emit("refresh");
}
</script>

<template>
  <n-modal
    v-model:show="show_model"
    :auto-focus="false"
    @after-enter="on_modal_enter"
  >
    <n-card
      style="width: 640px"
      :bordered="false"
      size="small"
      role="dialog"
      aria-modal="true"
    >
      <template #header>
        <n-flex align="center" :wrap="false">
          <span>
            {{
              is_editing ? t("wan_link.edit_title") : t("wan_link.create_title")
            }}
          </span>
          <n-tag size="small" round>
            {{ attach_iface_name }}
          </n-tag>
        </n-flex>
      </template>

      <n-alert v-if="!link_active" type="warning" style="margin-bottom: 12px">
        {{ t("wan_link.inactive_hint") }}
      </n-alert>

      <n-tabs type="line" animated>
        <n-tab-pane name="basic" :tab="t('wan_link.tab_basic')">
          <n-form :model="config">
            <n-form-item :label="t('wan_link.name')">
              <n-input
                v-model:value="config.name"
                :placeholder="t('wan_link.name_placeholder')"
              />
            </n-form-item>
            <n-form-item :label="t('wan_link.attach_iface')">
              <n-input :value="attach_iface_name" disabled />
            </n-form-item>
            <n-form-item :label="t('wan_link.kind')">
              <n-select
                :value="kind_config.t"
                :options="kind_options"
                @update:value="on_kind_change"
              />
            </n-form-item>
          </n-form>
        </n-tab-pane>

        <n-tab-pane :name="is_ppp ? 'ppp' : 'v4'" :tab="session_tab_label">
          <n-form v-if="is_ppp">
            <n-grid :cols="2" :x-gap="12">
              <n-form-item-gi :label="t('common.enable')">
                <n-switch
                  :value="v4.enable && v4_model.t === 'ipcp'"
                  @update:value="on_ppp_enable"
                />
              </n-form-item-gi>
              <n-form-item-gi :label="t('wan_link.default_route')">
                <n-switch
                  :value="v4_model.t === 'ipcp' && v4_model.default_router"
                  :disabled="!ppp_v4_enabled"
                  @update:value="on_ipcp_default_route"
                />
              </n-form-item-gi>
            </n-grid>
          </n-form>

          <template v-if="kind_config.t === 'pppoe_native'">
            <n-form :model="config">
              <n-form-item :label="t('wan_link.username')">
                <n-input
                  :type="frontEndStore.presentation_mode ? 'password' : 'text'"
                  show-password-on="click"
                  v-model:value="kind_config.username"
                />
              </n-form-item>
              <n-form-item :label="t('wan_link.password')">
                <n-input
                  :type="frontEndStore.presentation_mode ? 'password' : 'text'"
                  show-password-on="click"
                  v-model:value="kind_config.password"
                />
              </n-form-item>
              <n-form-item :label="t('wan_link.mru')">
                <n-input-number
                  v-model:value="kind_config.requested_mru"
                  :min="576"
                  :max="1500"
                  style="width: 100%"
                />
              </n-form-item>
              <n-form-item>
                <template #label>
                  <Notice>
                    {{ t("wan_link.ac_name") }}
                    <template #msg>{{ t("wan_link.ac_name_tip") }}</template>
                  </Notice>
                </template>
                <n-input v-model:value="kind_config.ac_name" />
              </n-form-item>
              <n-form-item :label="t('wan_link.lcp_echo_interval')">
                <n-input-number
                  v-model:value="kind_config.lcp_echo_interval"
                  :min="0"
                  style="width: 100%"
                />
              </n-form-item>
              <n-form-item :label="t('wan_link.redial_backoff')">
                <n-input-number
                  v-model:value="kind_config.redial_backoff_base_secs"
                  :min="0"
                  style="width: 100%"
                />
              </n-form-item>
            </n-form>
          </template>

          <template v-else-if="kind_config.t === 'pppd'">
            <n-form :model="config">
              <n-form-item
                :label="t('wan_link.ppp_iface_name')"
                :validation-status="
                  ppp_iface_name_conflict ? 'error' : undefined
                "
                :feedback="ppp_iface_name_conflict"
              >
                <n-input
                  v-model:value="kind_config.ppp_iface_name"
                  :disabled="ppp_iface_locked"
                />
              </n-form-item>
              <n-form-item :label="t('wan_link.username')">
                <n-input
                  :type="frontEndStore.presentation_mode ? 'password' : 'text'"
                  show-password-on="click"
                  v-model:value="kind_config.peer_id"
                />
              </n-form-item>
              <n-form-item :label="t('wan_link.password')">
                <n-input
                  :type="frontEndStore.presentation_mode ? 'password' : 'text'"
                  show-password-on="click"
                  v-model:value="kind_config.password"
                />
              </n-form-item>
              <n-form-item>
                <template #label>
                  <Notice>
                    {{ t("wan_link.ac_name") }}
                    <template #msg>{{ t("wan_link.ac_name_tip") }}</template>
                  </Notice>
                </template>
                <n-input
                  :type="frontEndStore.presentation_mode ? 'password' : 'text'"
                  show-password-on="click"
                  v-model:value="kind_config.ac"
                />
              </n-form-item>
              <n-form-item :label="t('wan_link.plugin')">
                <n-select
                  v-model:value="kind_config.plugin"
                  :options="pluginOptions"
                />
              </n-form-item>
            </n-form>
          </template>

          <n-form v-else>
            <n-form-item :label="t('common.enable')">
              <n-switch :value="v4.enable" @update:value="on_v4_enable" />
            </n-form-item>
            <template v-if="v4.enable">
              <n-form-item :label="t('wan_link.v4_mode')">
                <n-select
                  :value="v4_model.t"
                  :options="v4_model_options"
                  @update:value="select_v4_model"
                />
              </n-form-item>

              <template v-if="v4_model.t === 'static'">
                <n-form-item :label="t('wan_link.static_ip')">
                  <IpEdit
                    v-model:ip="v4_model.ipv4"
                    v-model:mask="static_mask"
                    :mask_max="32"
                  />
                </n-form-item>
                <n-form-item :label="t('wan_link.default_route')">
                  <n-switch v-model:value="v4_model.default_router" />
                </n-form-item>
                <n-form-item
                  v-if="v4_model.default_router"
                  :label="t('wan_link.route_ip')"
                >
                  <IpEdit v-model:ip="v4_model.default_router_ip" />
                </n-form-item>
              </template>

              <template v-else-if="v4_model.t === 'dhcp_client'">
                <n-alert type="warning" style="margin-bottom: 12px">
                  {{ t("wan_link.dhcp_warn") }}
                </n-alert>
                <n-form-item :label="t('wan_link.default_route')">
                  <n-switch v-model:value="v4_model.default_router" />
                </n-form-item>
                <n-form-item :label="t('wan_link.dhcp_hostname')">
                  <n-input v-model:value="v4_model.hostname" />
                </n-form-item>
              </template>
            </template>
          </n-form>
        </n-tab-pane>

        <n-tab-pane name="pd" :tab="t('wan_link.tab_pd')">
          <n-form>
            <n-form-item :label="t('common.enable')">
              <n-switch v-model:value="pd.enable" />
            </n-form-item>
            <template v-if="pd.enable">
              <n-form-item :label="t('wan_link.mac')">
                <n-input
                  :value="pd.mac"
                  @update:value="
                    (value: string) => (pd.mac = formatMacAddress(value))
                  "
                />
              </n-form-item>
              <n-form-item :label="t('wan_link.expected_pd_len')">
                <n-input-number
                  v-model:value="pd.expected_pd_len"
                  :min="56"
                  :max="64"
                  :step="1"
                  :precision="0"
                  style="width: 100%"
                />
              </n-form-item>
            </template>
          </n-form>
        </n-tab-pane>

        <n-tab-pane name="nat" :tab="t('wan_link.tab_nat')">
          <n-form>
            <n-form-item :label="t('common.enable')">
              <n-switch :value="nat.enable" @update:value="on_nat_enable" />
            </n-form-item>
            <template v-if="nat.enable">
              <n-form-item :label="t('wan_link.nat_tcp_range')">
                <PortRange v-model:range="nat_tcp_range" />
              </n-form-item>
              <n-form-item :label="t('wan_link.nat_udp_range')">
                <PortRange v-model:range="nat_udp_range" />
              </n-form-item>
              <n-form-item :label="t('wan_link.nat_icmp_range')">
                <PortRange v-model:range="nat_icmp_range" />
              </n-form-item>
            </template>
          </n-form>
        </n-tab-pane>

        <n-tab-pane name="firewall" :tab="t('wan_link.tab_firewall')">
          <n-form>
            <n-form-item :label="t('common.enable')">
              <n-switch v-model:value="firewall.enable" />
            </n-form-item>
          </n-form>
        </n-tab-pane>

        <n-tab-pane name="mss" :tab="t('wan_link.tab_mss')">
          <n-form>
            <n-form-item :label="t('common.enable')">
              <n-switch v-model:value="mss.enable" />
            </n-form-item>
            <template v-if="mss.enable">
              <n-form-item v-if="is_ppp" :label="t('wan_link.mss_auto')">
                <n-switch :value="mss_auto" @update:value="set_mss_auto" />
              </n-form-item>
              <n-form-item
                v-if="!mss_auto"
                :label="t('wan_link.mss_clamp_size')"
              >
                <n-input-number
                  v-model:value="mss.clamp_size"
                  :min="536"
                  :max="1500"
                  :show-button="false"
                  style="width: 100%"
                />
              </n-form-item>
            </template>
          </n-form>
        </n-tab-pane>
      </n-tabs>

      <template #footer>
        <n-flex justify="space-between">
          <n-popconfirm v-if="is_editing" @positive-click="remove_config">
            <template #trigger>
              <n-button round type="error">
                {{ t("common.delete") }}
              </n-button>
            </template>
            {{ t("wan_link.delete_confirm") }}
          </n-popconfirm>
          <span v-else />
          <n-flex>
            <n-button round @click="show_model = false">
              {{ t("common.cancel") }}
            </n-button>
            <n-button
              round
              type="success"
              :disabled="!is_modified"
              @click="save_config"
            >
              {{ t("common.save") }}
            </n-button>
          </n-flex>
        </n-flex>
      </template>
    </n-card>
  </n-modal>
</template>
