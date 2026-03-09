<script lang="ts" setup>
import {
  get_certs,
  delete_cert,
  issue_cert,
  cancel_cert,
  revoke_cert,
  renew_cert,
} from "@/api/cert/order";
import type { CertConfig } from "@landscape-router/types/api/schemas";
import { h, ref, onMounted, onUnmounted, computed, watch } from "vue";
import { useI18n } from "vue-i18n";
import {
  NButton,
  NTag,
  NFlex,
  NPopconfirm,
  type DataTableColumns,
} from "naive-ui";
import CertOrderEditModal from "@/components/cert/order/CertOrderEditModal.vue";
import CertInfoModal from "@/components/cert/order/CertInfoModal.vue";
import { useFrontEndStore } from "@/stores/front_end_config";

const items = ref<CertConfig[]>([]);
const { t } = useI18n();
const frontEndStore = useFrontEndStore();
const show_edit_modal = ref(false);
const edit_id = ref<string | null>(null);
const show_info_modal = ref(false);
const current_info_cert = ref<CertConfig | null>(null);
const loading_ids = ref<Set<string>>(new Set());
let poll_timer: ReturnType<typeof setInterval> | null = null;
let refresh_promise: Promise<void> | null = null;
let refresh_queued = false;

const has_processing = computed(() =>
  items.value.some((item) => item.status === "processing"),
);

async function refresh() {
  if (refresh_promise) {
    refresh_queued = true;
    await refresh_promise;
    return;
  }

  refresh_promise = (async () => {
    do {
      refresh_queued = false;
      items.value = await get_certs();
    } while (refresh_queued);
  })();

  try {
    await refresh_promise;
  } finally {
    refresh_promise = null;
  }
}

function start_polling() {
  if (poll_timer) return;
  poll_timer = setInterval(refresh, 5000);
}

function stop_polling() {
  if (poll_timer) {
    clearInterval(poll_timer);
    poll_timer = null;
  }
}

watch(has_processing, (val) => {
  if (val) {
    start_polling();
  } else {
    stop_polling();
  }
});

onMounted(async () => {
  await refresh();
});

onUnmounted(() => {
  stop_polling();
});

function status_type(status?: string) {
  switch (status) {
    case "valid":
      return "success";
    case "pending":
    case "ready":
    case "processing":
      return "warning";
    case "cancelled":
      return "default";
    case "invalid":
    case "expired":
    case "revoked":
      return "error";
    default:
      return "default";
  }
}

function cert_type_label(ct?: CertConfig["cert_type"]) {
  if (!ct) return "-";
  if (ct.t === "acme") return t("cert.type_acme");
  if (ct.t === "manual") return t("cert.type_manual");
  return "-";
}

function cert_type_tag_type(ct?: CertConfig["cert_type"]) {
  if (!ct) return "default";
  return ct.t === "acme" ? "info" : "success";
}

function bool_label(v?: boolean) {
  return v ? t("common.enable") : t("common.disable");
}

function is_acme(row: CertConfig) {
  return row.cert_type?.t === "acme";
}

function format_ts(ts?: number | null) {
  if (!ts) return "-";
  return new Date(ts * 1000).toLocaleDateString();
}

function setLoading(id: string, val: boolean) {
  if (val) {
    loading_ids.value.add(id);
  } else {
    loading_ids.value.delete(id);
  }
  loading_ids.value = new Set(loading_ids.value);
}

async function do_issue(id: string) {
  setLoading(id, true);
  try {
    await issue_cert(id);
    await refresh();
  } finally {
    setLoading(id, false);
  }
}

async function do_renew(id: string) {
  setLoading(id, true);
  try {
    await renew_cert(id);
    await refresh();
  } finally {
    setLoading(id, false);
  }
}

async function do_cancel(id: string) {
  setLoading(id, true);
  try {
    await cancel_cert(id);
    await refresh();
  } finally {
    setLoading(id, false);
  }
}

async function do_revoke(id: string) {
  setLoading(id, true);
  try {
    await revoke_cert(id);
    await refresh();
  } finally {
    setLoading(id, false);
  }
}

async function do_delete(id: string) {
  await delete_cert(id);
  await refresh();
}

function open_edit(id: string | null) {
  edit_id.value = id;
  show_edit_modal.value = true;
}

function open_info(cert: CertConfig) {
  current_info_cert.value = cert;
  show_info_modal.value = true;
}

const columns = computed<DataTableColumns<CertConfig>>(() => [
  {
    title: t("cert.cert_name"),
    key: "name",
    minWidth: 120,
    ellipsis: { tooltip: true },
    render(row) {
      return frontEndStore.MASK_INFO(row.name);
    },
  },
  {
    title: t("cert.cert_type"),
    key: "cert_type",
    width: 90,
    render(row) {
      return h(
        NTag,
        { size: "small", type: cert_type_tag_type(row.cert_type) },
        () => cert_type_label(row.cert_type),
      );
    },
  },
  {
    title: t("cert.cert_domains"),
    key: "domains",
    minWidth: 180,
    render(row) {
      return h(NFlex, { size: "small", wrap: true }, () =>
        (row.domains ?? []).map((d: string) =>
          h(NTag, { size: "small", bordered: false }, () =>
            frontEndStore.MASK_INFO(d),
          ),
        ),
      );
    },
  },
  {
    title: t("cert.for_api"),
    key: "for_api",
    width: 90,
    render(row) {
      return h(
        NTag,
        { size: "small", type: row.for_api ? "success" : "default" },
        () => bool_label(row.for_api),
      );
    },
  },
  {
    title: t("cert.for_gateway"),
    key: "for_gateway",
    width: 90,
    render(row) {
      return h(
        NTag,
        { size: "small", type: row.for_gateway ? "success" : "default" },
        () => bool_label(row.for_gateway),
      );
    },
  },
  {
    title: t("cert.cert_status"),
    key: "status",
    width: 100,
    render(row) {
      return h(NTag, { size: "small", type: status_type(row.status) }, () =>
        t(`cert.status_${row.status}`),
      );
    },
  },
  {
    title: t("cert.cert_issued_at"),
    key: "issued_at",
    width: 110,
    render(row) {
      return format_ts(row.issued_at);
    },
  },
  {
    title: t("cert.cert_expires"),
    key: "expires_at",
    width: 110,
    render(row) {
      return format_ts(row.expires_at);
    },
  },
  {
    title: t("common.status"),
    key: "actions",
    width: 320,
    fixed: "right",
    render(row) {
      const id = row.id!;
      const is_loading = loading_ids.value.has(id);
      const btns: any[] = [];

      btns.push(
        h(
          NButton,
          {
            size: "small",
            secondary: true,
            onClick: () => open_info(row),
          },
          () => t("cert.action_view"),
        ),
      );

      // Issue: pending | invalid | expired | revoked (ACME only)
      if (
        is_acme(row) &&
        (row.status === "pending" ||
          row.status === "invalid" ||
          row.status === "expired" ||
          row.status === "revoked" ||
          row.status === "cancelled")
      ) {
        btns.push(
          h(
            NButton,
            {
              size: "small",
              type: "success",
              secondary: true,
              loading: is_loading,
              onClick: () => do_issue(id),
            },
            () => t("cert.action_issue"),
          ),
        );
      }

      // Renew: valid | expired (ACME only)
      if (
        is_acme(row) &&
        (row.status === "valid" || row.status === "expired")
      ) {
        btns.push(
          h(
            NButton,
            {
              size: "small",
              type: "info",
              secondary: true,
              loading: is_loading,
              onClick: () => do_renew(id),
            },
            () => t("cert.action_renew"),
          ),
        );
      }

      if (is_acme(row) && row.status === "processing") {
        btns.push(
          h(
            NPopconfirm,
            { onPositiveClick: () => do_cancel(id) },
            {
              trigger: () =>
                h(
                  NButton,
                  {
                    size: "small",
                    type: "warning",
                    secondary: true,
                    loading: is_loading,
                  },
                  () => t("cert.action_cancel"),
                ),
              default: () => t("cert.confirm_cancel"),
            },
          ),
        );
      }

      // Revoke: valid (ACME only, with confirmation)
      if (is_acme(row) && row.status === "valid") {
        btns.push(
          h(
            NPopconfirm,
            { onPositiveClick: () => do_revoke(id) },
            {
              trigger: () =>
                h(
                  NButton,
                  {
                    size: "small",
                    type: "warning",
                    secondary: true,
                    loading: is_loading,
                  },
                  () => t("cert.action_revoke"),
                ),
              default: () => t("cert.confirm_revoke"),
            },
          ),
        );
      }

      // Edit: always
      btns.push(
        h(
          NButton,
          {
            size: "small",
            secondary: true,
            onClick: () => open_edit(id),
          },
          () => t("common.edit"),
        ),
      );

      // Delete: always (with confirmation)
      btns.push(
        h(
          NPopconfirm,
          { onPositiveClick: () => do_delete(id) },
          {
            trigger: () =>
              h(
                NButton,
                { size: "small", type: "error", secondary: true },
                () => t("common.delete"),
              ),
            default: () => t("common.confirm_delete"),
          },
        ),
      );

      return h(NFlex, { size: "small", wrap: false }, () => btns);
    },
  },
]);
</script>

<template>
  <n-flex vertical style="flex: 1">
    <n-flex>
      <n-button @click="open_edit(null)">
        {{ t("common.create") }}
      </n-button>
    </n-flex>

    <n-data-table
      :columns="columns"
      :data="items"
      :bordered="true"
      :single-line="false"
      size="small"
      :scroll-x="960"
    />

    <CertOrderEditModal
      :rule_id="edit_id"
      @refresh="refresh"
      v-model:show="show_edit_modal"
    />
    <CertInfoModal :cert="current_info_cert" v-model:show="show_info_modal" />
  </n-flex>
</template>
