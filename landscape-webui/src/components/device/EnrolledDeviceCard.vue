<script setup lang="ts">
import { ref } from "vue";
import type { EnrolledDevice } from "landscape-types/api/schemas";
import {
  delete_enrolled_device,
  validate_enrolled_device_ip,
} from "@/api/enrolled_device";
import { useFrontEndStore } from "@/stores/front_end_config";
import { useI18n } from "vue-i18n";
import { Settings, TrashCan } from "@vicons/carbon";
import EnrolledDeviceEditModal from "./EnrolledDeviceEditModal.vue";
import { computed, onMounted } from "vue";
import { useEnrolledDeviceStore } from "@/stores/enrolled_device";

const enrolledDeviceStore = useEnrolledDeviceStore();

const { t } = useI18n();
const frontEndStore = useFrontEndStore();
const isValid = ref<boolean | null>(null);

const displayName = computed(() => {
  if (frontEndStore.presentation_mode && props.rule.fake_name) {
    return props.rule.fake_name;
  }
  return props.rule.name;
});

type Props = {
  rule: EnrolledDevice;
  show_action?: boolean;
};

const props = withDefaults(defineProps<Props>(), {
  show_action: true,
});

const emit = defineEmits(["refresh"]);

const show_edit_modal = ref(false);

async function validate() {
  if (props.rule.iface_name && props.rule.ipv4) {
    try {
      isValid.value = await validate_enrolled_device_ip(
        props.rule.iface_name,
        props.rule.ipv4,
      );
    } catch (e) {
      console.error("Async validation failed", e);
    }
  } else {
    isValid.value = true;
  }
}

onMounted(() => {
  validate();
});

async function del() {
  if (props.rule.id) {
    await delete_enrolled_device(props.rule.id);
    await enrolledDeviceStore.UPDATE_INFO();
    emit("refresh");
  }
}
</script>

<template>
  <n-card size="small" hoverable>
    <template #header>
      <n-space align="center">
        <n-avatar round size="small" color="#18a058">
          {{ displayName.charAt(0).toUpperCase() }}
        </n-avatar>
        <n-ellipsis style="max-width: 150px">
          {{ displayName }}
        </n-ellipsis>
        <n-tag
          v-if="frontEndStore.presentation_mode && rule.fake_name"
          size="small"
          type="info"
          round
        >
          {{ t("common.private_mode") || "隐私模式" }}
        </n-tag>
        <n-tooltip v-if="isValid === false" trigger="hover">
          <template #trigger>
            <n-tag size="small" type="error" round>
              {{ t("enrolled_device.invalid_status") }}
            </n-tag>
          </template>
          {{
            t("enrolled_device.ipv4_out_of_range", { iface: rule.iface_name })
          }}
        </n-tooltip>
      </n-space>
    </template>

    <n-descriptions
      label-style="width: 80px"
      bordered
      label-placement="left"
      :column="1"
      size="small"
    >
      <n-descriptions-item :label="t('enrolled_device.mac')">
        <code>{{ frontEndStore.MASK_INFO(rule.mac) }}</code>
      </n-descriptions-item>

      <n-descriptions-item
        v-if="rule.iface_name"
        :label="t('enrolled_device.iface')"
      >
        <n-tag size="small" type="primary" :bordered="false">{{
          rule.iface_name
        }}</n-tag>
      </n-descriptions-item>

      <n-descriptions-item v-if="rule.ipv4" :label="t('enrolled_device.ipv4')">
        {{ frontEndStore.MASK_INFO(rule.ipv4) }}
      </n-descriptions-item>

      <n-descriptions-item v-if="rule.ipv6" :label="t('enrolled_device.ipv6')">
        <n-ellipsis style="max-width: 200px">
          {{ frontEndStore.MASK_INFO(rule.ipv6) }}
        </n-ellipsis>
      </n-descriptions-item>

      <n-descriptions-item
        v-if="rule.tag && rule.tag.length > 0"
        :label="t('enrolled_device.tag')"
      >
        <n-space size="small">
          <n-tag
            v-for="tag in rule.tag"
            :key="tag"
            size="tiny"
            :bordered="false"
            type="success"
            round
          >
            {{ tag }}
          </n-tag>
        </n-space>
      </n-descriptions-item>

      <n-descriptions-item
        v-if="rule.remark"
        :label="t('enrolled_device.remark')"
      >
        <n-ellipsis :line-clamp="1">
          {{ rule.remark }}
        </n-ellipsis>
      </n-descriptions-item>
    </n-descriptions>

    <template v-if="show_action" #header-extra>
      <n-flex>
        <n-button
          size="small"
          quaternary
          circle
          type="info"
          @click="show_edit_modal = true"
        >
          <template #icon>
            <Settings />
          </template>
        </n-button>

        <n-popconfirm @positive-click="del()">
          <template #trigger>
            <n-button size="small" quaternary circle type="error">
              <template #icon>
                <TrashCan />
              </template>
            </n-button>
          </template>
          {{ t("enrolled_device.delete_confirm") }}
        </n-popconfirm>
      </n-flex>
    </template>
  </n-card>

  <EnrolledDeviceEditModal
    @refresh="emit('refresh')"
    :rule_id="rule.id ?? null"
    v-model:show="show_edit_modal"
  />
</template>

<style scoped>
code {
  font-family: monospace;
  background: rgba(0, 0, 0, 0.05);
  padding: 2px 4px;
  border-radius: 4px;
}
</style>
