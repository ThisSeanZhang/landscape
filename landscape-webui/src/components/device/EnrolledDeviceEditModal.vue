<script setup lang="ts">
import { useMessage } from "naive-ui";
import { isIP, isIPv4 } from "is-ip";
import { computed, ref } from "vue";
import type { EnrolledDevice } from "@landscape-router/types/api/schemas";
import {
  get_enrolled_device_by_id,
  create_enrolled_device,
  update_enrolled_device,
  validate_enrolled_device_ip,
} from "@/api/enrolled_device";
import { get_all_dhcp_v4_status } from "@/api/service_dhcp_v4";
import { useI18n } from "vue-i18n";
import { useEnrolledDeviceStore } from "@/stores/enrolled_device";

const enrolledDeviceStore = useEnrolledDeviceStore();

type Props = {
  rule_id: string | null;
  initialValues?: {
    mac?: string;
    ipv4?: string;
    name?: string;
    iface_name?: string;
  };
};

const props = defineProps<Props>();
const message = useMessage();
const { t } = useI18n();
const emit = defineEmits(["refresh"]);

const show = defineModel<boolean>("show", { required: true });

const origin_rule_json = ref<string>("");
const rule = ref<EnrolledDevice>({
  name: "",
  mac: "",
  tag: [],
});

const commit_spin = ref(false);
const ifaceOptions = ref<{ label: string; value: string }[]>([]);

const isModified = computed(() => {
  return JSON.stringify(rule.value) !== origin_rule_json.value;
});

async function enter() {
  // 加载可用的网卡列表
  try {
    const statusMap = await get_all_dhcp_v4_status();
    ifaceOptions.value = Array.from(statusMap.keys()).map((name) => ({
      label: name,
      value: name,
    }));
  } catch (e) {
    console.error("Failed to fetch DHCP status", e);
  }

  if (props.rule_id) {
    const fetched = await get_enrolled_device_by_id(props.rule_id);
    if (fetched) {
      rule.value = fetched;
    }
  } else {
    rule.value = {
      name: props.initialValues?.name ?? "",
      mac: props.initialValues?.mac ?? "",
      tag: [],
      remark: "",
      fake_name: "",
      ipv4: props.initialValues?.ipv4 ?? undefined,
      ipv6: undefined,
      iface_name: props.initialValues?.iface_name ?? undefined,
    };
  }
  origin_rule_json.value = JSON.stringify(rule.value);
}

const formRef = ref();

const macRule = {
  trigger: ["input", "blur"],
  validator(_: unknown, value: string) {
    if (!value) return new Error(t("enrolled_device.mac_required"));
    const macRegex = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;
    if (!macRegex.test(value))
      return new Error(t("enrolled_device.mac_invalid"));
    return true;
  },
};

const ipRule = {
  trigger: ["input", "blur"],
  async validator(_: unknown, value: string) {
    if (value && !isIP(value))
      return new Error(t("enrolled_device.ipv4_invalid"));

    if (value && rule.value.iface_name && isIPv4(value)) {
      try {
        const isValid = await validate_enrolled_device_ip(
          rule.value.iface_name,
          value,
        );
        if (!isValid) {
          return new Error(
            t("enrolled_device.ipv4_out_of_range", {
              iface: rule.value.iface_name,
            }),
          );
        }
      } catch (e) {
        console.error("IP validation failed", e);
      }
    }
    return true;
  },
};

const rules = {
  name: {
    required: true,
    message: t("enrolled_device.name_required"),
    trigger: "blur",
  },
  mac: macRule,
  ipv4: ipRule,
  // ipv6: ipRule, // DHCPv6 尚未实现
};

async function saveRule() {
  try {
    await formRef.value?.validate();
    commit_spin.value = true;
    if (props.rule_id) {
      await update_enrolled_device(props.rule_id, rule.value);
    } else {
      await create_enrolled_device(rule.value);
    }
    message.success(t("enrolled_device.save_success"));
    show.value = false;
    await enrolledDeviceStore.UPDATE_INFO();
    emit("refresh");
  } catch (e) {
    console.error(e);
  } finally {
    commit_spin.value = false;
  }
}
</script>

<template>
  <n-modal
    :auto-focus="false"
    v-model:show="show"
    style="width: 600px"
    preset="card"
    :title="
      props.rule_id
        ? t('enrolled_device.edit_title')
        : t('enrolled_device.add_title')
    "
    @after-enter="enter"
  >
    <n-form
      v-if="rule"
      :rules="rules"
      ref="formRef"
      :model="rule"
      label-placement="left"
      label-width="100"
    >
      <n-grid :cols="2" x-gap="12">
        <n-form-item-gi
          :span="2"
          :label="t('enrolled_device.name')"
          path="name"
        >
          <n-input
            v-model:value="rule.name"
            :placeholder="t('enrolled_device.name_placeholder')"
          />
        </n-form-item-gi>

        <n-form-item-gi :span="2" :label="t('enrolled_device.mac')" path="mac">
          <n-input
            v-model:value="rule.mac"
            :placeholder="t('enrolled_device.mac_placeholder')"
          />
        </n-form-item-gi>

        <n-form-item-gi
          :span="2"
          :label="t('enrolled_device.iface')"
          path="iface_name"
        >
          <n-select
            v-model:value="rule.iface_name"
            :options="ifaceOptions"
            :placeholder="t('enrolled_device.iface_placeholder')"
            clearable
          />
        </n-form-item-gi>

        <n-form-item-gi
          :span="2"
          :label="t('enrolled_device.fake_name')"
          path="fake_name"
        >
          <n-input
            v-model:value="rule.fake_name"
            :placeholder="t('enrolled_device.fake_name_placeholder')"
          />
        </n-form-item-gi>

        <n-form-item-gi :label="t('enrolled_device.ipv4')" path="ipv4">
          <n-input
            v-model:value="rule.ipv4"
            :placeholder="t('enrolled_device.ipv4_placeholder')"
          />
        </n-form-item-gi>

        <!-- DHCPv6 尚未实现，暂时隐藏 IPv6 映射
        <n-form-item-gi :label="t('enrolled_device.ipv6')" path="ipv6">
          <n-input
            v-model:value="rule.ipv6"
            :placeholder="t('enrolled_device.ipv6_placeholder')"
          />
        </n-form-item-gi>
        -->

        <n-form-item-gi :span="2" :label="t('enrolled_device.tag')" path="tag">
          <n-dynamic-tags v-model:value="rule.tag" />
        </n-form-item-gi>

        <n-form-item-gi
          :span="2"
          :label="t('enrolled_device.remark')"
          path="remark"
        >
          <n-input
            v-model:value="rule.remark"
            type="textarea"
            :placeholder="t('enrolled_device.remark_placeholder')"
          />
        </n-form-item-gi>
      </n-grid>
    </n-form>

    <template #footer>
      <n-flex justify="end">
        <n-space>
          <n-button @click="show = false">{{
            t("enrolled_device.cancel")
          }}</n-button>
          <n-button
            type="primary"
            :loading="commit_spin"
            @click="saveRule"
            :disabled="!isModified"
          >
            {{ t("enrolled_device.save") }}
          </n-button>
        </n-space>
      </n-flex>
    </template>
  </n-modal>
</template>
