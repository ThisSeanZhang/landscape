<script setup lang="ts">
import { get_geo_ip_config, push_geo_ip_config } from "@/api/geo/ip";
import type {
  GeoIpSourceConfig,
  GeoIpDirectItem,
} from "@landscape-router/types/api/schemas";
import { computed, ref } from "vue";
import { FormInst, FormRules } from "naive-ui";
import { useI18n } from "vue-i18n";
import ConfigModal from "@/components/common/ConfigModal.vue";

const emit = defineEmits(["refresh"]);

const show = defineModel<boolean>("show", { required: true });
interface Prop {
  id: string | null;
}
const props = defineProps<Prop>();
const commit_spin = ref(false);
const { t } = useI18n();

const rule = ref<GeoIpSourceConfig>();
const rule_json = ref<string>("");

const sourceType = ref<"url" | "direct">("url");

async function enter() {
  if (props.id !== null) {
    rule.value = await get_geo_ip_config(props.id);
    if (rule.value.source.t === "url") {
      rule.value.source.format = rule.value.source.format || "dat";
      rule.value.source.txt_key = rule.value.source.txt_key || null;
    }
    sourceType.value = rule.value.source.t;
  } else {
    sourceType.value = "url";
    rule.value = {
      name: "",
      enable: true,
      source: {
        t: "url",
        url: "",
        next_update_at: 0,
        format: "dat",
        txt_key: null,
      },
    };
  }
  rule_json.value = JSON.stringify(rule.value);
}

function switchSourceType(t: "url" | "direct") {
  if (!rule.value) return;
  if (t === "url") {
    rule.value.source = {
      t: "url",
      url: "",
      next_update_at: 0,
      format: "dat",
      txt_key: null,
    };
  } else {
    rule.value.source = { t: "direct", data: [] };
  }
}

const isModified = computed(() => {
  return JSON.stringify(rule.value) !== rule_json.value;
});

const rule_enabled = computed({
  get() {
    return rule.value?.enable ?? false;
  },
  set(value: boolean) {
    if (rule.value) {
      rule.value.enable = value;
    }
  },
});

async function saveRule() {
  if (!formRef.value) return;
  try {
    await formRef.value.validate();
  } catch (err) {
    return;
  }

  if (rule.value) {
    try {
      commit_spin.value = true;
      await push_geo_ip_config(rule.value);
      show.value = false;
      emit("refresh");
    } finally {
      commit_spin.value = false;
    }
  }
}

// Direct mode helpers
function addDirectItem() {
  if (!rule.value || rule.value.source.t !== "direct") return;
  rule.value.source.data.push({ key: "", values: [] });
}

function removeDirectItem(index: number) {
  if (!rule.value || rule.value.source.t !== "direct") return;
  rule.value.source.data.splice(index, 1);
}

function addIpToItem(item: GeoIpDirectItem) {
  item.values.push({ ip: "", prefix: 32 });
}

function removeIpFromItem(item: GeoIpDirectItem, index: number) {
  item.values.splice(index, 1);
}

const formRef = ref<FormInst | null>(null);

const rules: FormRules = {
  name: [
    {
      required: true,
      validator: (rule, value: string) => {
        if (!value) {
          return new Error(t("geo.common.name_required"));
        }
        const nameRegex = /^[a-zA-Z0-9._-]+$/;
        if (!nameRegex.test(value)) {
          return new Error(t("geo.common.name_invalid"));
        }
        return true;
      },
      trigger: ["input", "blur"],
    },
  ],
};
</script>
<template>
  <ConfigModal
    v-model:show="show"
    v-model:enabled="rule_enabled"
    :title="t('geo.geo_ip.title')"
    :switch-disabled="!rule"
    width="600px"
    @after-enter="enter"
  >
    <n-form
      v-if="rule"
      style="flex: 1"
      ref="formRef"
      :model="rule"
      :rules="rules"
      :cols="5"
    >
      <n-grid :cols="5">
        <n-form-item-gi :label="t('geo.common.source_type')" :span="5">
          <n-radio-group
            v-model:value="sourceType"
            @update:value="switchSourceType"
          >
            <n-radio value="url">{{ t("geo.common.source_url_mode") }}</n-radio>
            <n-radio value="direct">{{
              t("geo.common.source_direct_mode")
            }}</n-radio>
          </n-radio-group>
        </n-form-item-gi>

        <n-form-item-gi
          :label="t('geo.common.name_unique')"
          path="name"
          :span="5"
        >
          <n-input v-model:value="rule.name" clearable />
        </n-form-item-gi>

        <!-- URL mode -->
        <template v-if="rule.source.t === 'url'">
          <n-form-item-gi :label="t('geo.common.source_url')" :span="5">
            <n-input v-model:value="rule.source.url" clearable />
          </n-form-item-gi>
          <n-form-item-gi :label="t('geo.common.source_format')" :span="5">
            <n-radio-group v-model:value="rule.source.format">
              <n-radio value="dat">DAT</n-radio>
              <n-radio value="txt">TXT</n-radio>
            </n-radio-group>
          </n-form-item-gi>
          <n-form-item-gi
            v-if="rule.source.format === 'txt'"
            :label="t('geo.common.txt_key')"
            :span="5"
          >
            <n-input
              v-model:value="rule.source.txt_key"
              clearable
              :placeholder="t('geo.common.txt_key_placeholder')"
            />
          </n-form-item-gi>
        </template>

        <!-- Direct mode -->
        <template v-if="rule.source.t === 'direct'">
          <n-form-item-gi :label="t('geo.geo_ip.ip_list')" :span="5">
            <n-flex vertical style="width: 100%">
              <n-card
                v-for="(item, idx) in rule.source.data"
                :key="idx"
                size="small"
              >
                <template #header>
                  <n-input
                    v-model:value="item.key"
                    :placeholder="t('geo.common.key')"
                    size="small"
                  />
                </template>
                <template #header-extra>
                  <n-button
                    size="small"
                    type="error"
                    secondary
                    @click="removeDirectItem(idx)"
                  >
                    {{ t("geo.common.remove") }}
                  </n-button>
                </template>
                <n-flex vertical>
                  <n-flex
                    v-for="(ipItem, iIdx) in item.values"
                    :key="iIdx"
                    :wrap="false"
                    align="center"
                  >
                    <n-input
                      v-model:value="ipItem.ip"
                      :placeholder="t('geo.geo_ip.ip_placeholder')"
                      size="small"
                      style="flex: 1"
                    />
                    <n-input-number
                      v-model:value="ipItem.prefix"
                      :min="0"
                      :max="128"
                      size="small"
                      style="width: 100px"
                      :placeholder="t('geo.geo_ip.prefix_placeholder')"
                    />
                    <n-button
                      size="small"
                      type="error"
                      quaternary
                      @click="removeIpFromItem(item, iIdx)"
                    >
                      X
                    </n-button>
                  </n-flex>
                  <n-button size="small" dashed @click="addIpToItem(item)">
                    {{ t("geo.geo_ip.add_ip") }}
                  </n-button>
                </n-flex>
              </n-card>
              <n-button dashed @click="addDirectItem">
                {{ t("geo.common.add_key_group") }}
              </n-button>
            </n-flex>
          </n-form-item-gi>
        </template>
      </n-grid>
    </n-form>
    <template #footer>
      <n-flex justify="space-between">
        <n-button @click="show = false">{{ t("common.cancel") }}</n-button>
        <n-button
          :loading="commit_spin"
          @click="saveRule"
          :disabled="!isModified"
        >
          {{ t("common.save") }}
        </n-button>
      </n-flex>
    </template>
  </ConfigModal>
</template>
