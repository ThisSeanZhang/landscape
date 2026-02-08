<script setup lang="ts">
import { useMessage } from "naive-ui";
import { isIP } from "is-ip";
import { computed, ref } from "vue";
import { IpMacBinding } from "landscape-types/common/mac_binding";
import {
  get_mac_binding_by_id,
  create_mac_binding,
  update_mac_binding,
  validate_mac_binding_ip,
} from "@/api/mac_binding";
import { useI18n } from "vue-i18n";

type Props = {
  rule_id: string | null;
};

const props = defineProps<Props>();
const message = useMessage();
const { t } = useI18n();
const emit = defineEmits(["refresh"]);

const show = defineModel<boolean>("show", { required: true });

const origin_rule_json = ref<string>("");
const rule = ref<IpMacBinding>({
  name: "",
  mac: "",
  tag: [],
});

const commit_spin = ref(false);

const isModified = computed(() => {
  return JSON.stringify(rule.value) !== origin_rule_json.value;
});

async function enter() {
  if (props.rule_id) {
    const fetched = await get_mac_binding_by_id(props.rule_id);
    if (fetched) {
      rule.value = fetched;
    }
  } else {
    rule.value = {
      name: "",
      mac: "",
      tag: [],
      remark: "",
      fake_name: "",
      ipv4: undefined,
      ipv6: undefined,
    };
  }
  origin_rule_json.value = JSON.stringify(rule.value);
}

const formRef = ref();

const macRule = {
  trigger: ["input", "blur"],
  validator(_: unknown, value: string) {
    if (!value) return new Error("MAC 地址不能为空");
    const macRegex = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;
    if (!macRegex.test(value))
      return new Error("请输入有效的 MAC 地址 (XX:XX:XX:XX:XX:XX)");
    return true;
  },
};

const ipRule = {
  trigger: ["input", "blur"],
  async validator(_: unknown, value: string) {
    if (value && !isIP(value)) return new Error("请输入有效的 IP 地址");

    if (value && rule.value.iface_name && isIP(value) === 4) {
      try {
        const isValid = await validate_mac_binding_ip(
          rule.value.iface_name,
          value,
        );
        if (!isValid) {
          return new Error(
            `IP 地址不在网卡 ${rule.value.iface_name} 的 DHCP 网段范围内`,
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
    message: "请输入展示名称",
    trigger: "blur",
  },
  mac: macRule,
  ipv4: ipRule,
  ipv6: ipRule,
};

async function saveRule() {
  try {
    await formRef.value?.validate();
    commit_spin.value = true;
    if (props.rule_id) {
      await update_mac_binding(props.rule_id, rule.value);
    } else {
      await create_mac_binding(rule.value);
    }
    message.success(t("config.save_success") || "保存成功");
    show.value = false;
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
    title="设备管理"
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
        <n-form-item-gi :span="2" label="展示名称" path="name">
          <n-input v-model:value="rule.name" placeholder="例如: 我的手机" />
        </n-form-item-gi>

        <n-form-item-gi :span="2" label="MAC 地址" path="mac">
          <n-input v-model:value="rule.mac" placeholder="00:11:22:33:44:55" />
        </n-form-item-gi>

        <n-form-item-gi :span="2" label="所属网络" path="iface_name">
          <n-input
            v-model:value="rule.iface_name"
            placeholder="网卡名称 (可选), 例如: eth0"
            clearable
          />
        </n-form-item-gi>

        <n-form-item-gi :span="2" label="隐私名称" path="fake_name">
          <n-input
            v-model:value="rule.fake_name"
            placeholder="可选: 隐私模式下显示的名称"
          />
        </n-form-item-gi>

        <n-form-item-gi label="IPv4 映射" path="ipv4">
          <n-input v-model:value="rule.ipv4" placeholder="可选: 192.168.x.x" />
        </n-form-item-gi>

        <n-form-item-gi label="IPv6 映射" path="ipv6">
          <n-input v-model:value="rule.ipv6" placeholder="可选: IPv6 地址" />
        </n-form-item-gi>

        <n-form-item-gi :span="2" label="标签" path="tag">
          <n-dynamic-tags v-model:value="rule.tag" />
        </n-form-item-gi>

        <n-form-item-gi :span="2" label="备注" path="remark">
          <n-input
            v-model:value="rule.remark"
            type="textarea"
            placeholder="关于该设备的更多信息..."
          />
        </n-form-item-gi>
      </n-grid>
    </n-form>

    <template #footer>
      <n-flex justify="end">
        <n-space>
          <n-button @click="show = false">取消</n-button>
          <n-button
            type="primary"
            :loading="commit_spin"
            @click="saveRule"
            :disabled="!isModified"
          >
            保存
          </n-button>
        </n-space>
      </n-flex>
    </template>
  </n-modal>
</template>
