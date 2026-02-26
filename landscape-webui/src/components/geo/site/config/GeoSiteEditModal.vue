<script setup lang="ts">
import { get_geo_site_config, push_geo_site_config } from "@/api/geo/site";
import type {
  GeoSiteSourceConfig,
  GeoSiteSource,
  GeoSiteDirectItem,
  GeoSiteFileConfig,
} from "@landscape-router/types/api/schemas";
import { FormInst, FormRules } from "naive-ui";
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";

const emit = defineEmits(["refresh"]);

const show = defineModel<boolean>("show", { required: true });
interface Prop {
  id: string | null;
}
const props = defineProps<Prop>();
const commit_spin = ref(false);
const { t } = useI18n();

const rule = ref<GeoSiteSourceConfig>();
const rule_json = ref<string>("");

const sourceType = ref<"url" | "direct">("url");

async function enter() {
  if (props.id !== null) {
    rule.value = await get_geo_site_config(props.id);
    sourceType.value = rule.value.source.t;
  } else {
    sourceType.value = "url";
    rule.value = {
      id: null,
      update_at: new Date().getTime(),
      name: "",
      enable: true,
      source: { t: "url", url: "", next_update_at: 0, geo_keys: [] },
    };
  }
  rule_json.value = JSON.stringify(rule.value);
}

function switchSourceType(t: "url" | "direct") {
  if (!rule.value) return;
  if (t === "url") {
    rule.value.source = { t: "url", url: "", next_update_at: 0, geo_keys: [] };
  } else {
    rule.value.source = { t: "direct", data: [] };
  }
}

const isModified = computed(() => {
  return JSON.stringify(rule.value) !== rule_json.value;
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
      await push_geo_site_config(rule.value);
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

function addDomainToItem(item: GeoSiteDirectItem) {
  item.values.push({ match_type: "domain", value: "", attributes: [] });
}

function removeDomainFromItem(item: GeoSiteDirectItem, index: number) {
  item.values.splice(index, 1);
}

const formRef = ref<FormInst | null>(null);

const rules: FormRules = {
  name: [
    {
      required: true,
      validator: (rule, value: string) => {
        if (!value) {
          return new Error(t("geo_editor.common.name_required"));
        }
        const nameRegex = /^[a-zA-Z0-9._-]+$/;
        if (!nameRegex.test(value)) {
          return new Error(t("geo_editor.common.name_invalid"));
        }
        return true;
      },
      trigger: ["input", "blur"],
    },
  ],
};

const matchTypeOptions = [
  { label: "Domain", value: "domain" },
  { label: "Full", value: "full" },
  { label: "Plain", value: "plain" },
  { label: "Regex", value: "regex" },
];
</script>
<template>
  <n-modal
    v-model:show="show"
    style="width: 600px"
    preset="card"
    :title="t('geo_editor.geo_site.title')"
    size="small"
    :bordered="false"
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
        <n-form-item-gi :label="t('geo_editor.common.enable')" :offset="0" :span="1">
          <n-switch v-model:value="rule.enable">
            <template #checked> {{ t("geo_editor.common.enabled_yes") }} </template>
            <template #unchecked> {{ t("geo_editor.common.enabled_no") }} </template>
          </n-switch>
        </n-form-item-gi>
        <n-form-item-gi :label="t('geo_editor.common.source_type')" :span="4">
          <n-radio-group
            v-model:value="sourceType"
            @update:value="switchSourceType"
          >
            <n-radio value="url">{{ t("geo_editor.common.source_url_mode") }}</n-radio>
            <n-radio value="direct">{{ t("geo_editor.common.source_direct_mode") }}</n-radio>
          </n-radio-group>
        </n-form-item-gi>

        <n-form-item-gi
          :label="t('geo_editor.common.name_unique')"
          path="name"
          :span="5"
        >
          <n-input v-model:value="rule.name" clearable />
        </n-form-item-gi>

        <!-- URL mode -->
        <template v-if="rule.source.t === 'url'">
          <n-form-item-gi :label="t('geo_editor.common.source_url')" :span="5">
            <n-input v-model:value="rule.source.url" clearable />
          </n-form-item-gi>
        </template>

        <!-- Direct mode -->
        <template v-if="rule.source.t === 'direct'">
          <n-form-item-gi :label="t('geo_editor.geo_site.domain_list')" :span="5">
            <n-flex vertical style="width: 100%">
              <n-card
                v-for="(item, idx) in rule.source.data"
                :key="idx"
                size="small"
              >
                <template #header>
                  <n-input
                    v-model:value="item.key"
                    :placeholder="t('geo_editor.common.key')"
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
                    {{ t("geo_editor.common.remove") }}
                  </n-button>
                </template>
                <n-flex vertical>
                  <n-flex
                    v-for="(domain, dIdx) in item.values"
                    :key="dIdx"
                    :wrap="false"
                    align="center"
                  >
                    <n-select
                      v-model:value="domain.match_type"
                      :options="matchTypeOptions"
                      size="small"
                      style="width: 120px"
                    />
                    <n-input
                      v-model:value="domain.value"
                      :placeholder="t('geo_editor.geo_site.domain_placeholder')"
                      size="small"
                      style="flex: 1"
                    />
                    <n-button
                      size="small"
                      type="error"
                      quaternary
                      @click="removeDomainFromItem(item, dIdx)"
                    >
                      X
                    </n-button>
                  </n-flex>
                  <n-button size="small" dashed @click="addDomainToItem(item)">
                    {{ t("geo_editor.geo_site.add_domain") }}
                  </n-button>
                </n-flex>
              </n-card>
              <n-button dashed @click="addDirectItem">
                {{ t("geo_editor.common.add_key_group") }}
              </n-button>
            </n-flex>
          </n-form-item-gi>
        </template>
      </n-grid>
    </n-form>
    <template #footer>
      <n-flex justify="space-between">
        <n-button @click="show = false">{{ t("geo_editor.common.cancel") }}</n-button>
        <n-button
          :loading="commit_spin"
          @click="saveRule"
          :disabled="!isModified"
        >
          {{ t("geo_editor.common.save") }}
        </n-button>
      </n-flex>
    </template>
  </n-modal>
</template>
