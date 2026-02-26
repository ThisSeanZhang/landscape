<script setup lang="ts">
import { run_cmd } from "@/api/docker";
import { KeyValuePair } from "@/lib/common";
import { LAND_REDIRECT_ID_KEY } from "@/lib/docker";
import { DockerCmd } from "@landscape-router/types/api/schemas";
import { useDockerStore } from "@/stores/status_docker";
import { useNotification } from "naive-ui";
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";

const show_model = defineModel<boolean>("show", { required: true });

const props = defineProps<{
  image_name: string;
}>();

const emit = defineEmits(["refresh"]);

const dockerStore = useDockerStore();
const notification = useNotification();
const { t } = useI18n();

// 定义表单的状态
const formModel = ref<DockerCmd>();

async function on_modal_enter() {
  formModel.value = {
    image_name: props.image_name,
    restart: DockerRestartPolicy.NO,
    restart_max_retries: 3,
    container_name: undefined,
    ports: undefined,
    environment: undefined,
    volumes: undefined,
    labels: undefined,
    entrypoint: undefined,
    params: undefined,
  };
}

const save_loading = ref(false);
async function save_config() {
  if (formModel.value) {
    try {
      save_loading.value = true;
      await run_cmd(formModel.value);
      dockerStore.UPDATE_INFO();
      show_model.value = false;
    } finally {
      save_loading.value = false;
    }
  }
}

enum DockerRestartPolicy {
  NO = "no",
  ON_FAILURE = "on-failure",
  ON_FAILURE_WITH_MAX_RETRIES = "on-failure:<max-retries>",
  ALWAYS = "always",
  UNLESS_STOPPED = "unless-stopped",
}

const restrt_options = [
  {
    label: t("misc.docker_run.restart_no"),
    value: DockerRestartPolicy.NO,
  },
  {
    label: t("misc.docker_run.restart_on_failure"),
    value: DockerRestartPolicy.ON_FAILURE,
  },
  {
    label: t("misc.docker_run.restart_on_failure_max"),
    value: DockerRestartPolicy.ON_FAILURE_WITH_MAX_RETRIES,
  },
  {
    label: t("misc.docker_run.restart_always"),
    value: DockerRestartPolicy.ALWAYS,
  },
  {
    label: t("misc.docker_run.restart_unless_stopped"),
    value: DockerRestartPolicy.UNLESS_STOPPED,
  },
];

const has_edge_label = computed({
  get() {
    if (formModel.value?.labels) {
      for (const label of formModel.value.labels) {
        if (label.key === LAND_REDIRECT_ID_KEY) {
          return true;
        }
      }
    }

    return false;
  },
  set(new_value) {
    if (new_value) {
      if (formModel.value?.labels) {
        formModel.value?.labels.unshift({
          key: LAND_REDIRECT_ID_KEY,
          value: "",
        });
      } else {
        if (formModel.value) {
          formModel.value.labels = [
            {
              key: LAND_REDIRECT_ID_KEY,
              value: "",
            },
          ];
        }
      }
    } else {
      if (formModel.value?.labels) {
        formModel.value.labels = formModel.value.labels.filter(
          (e) => e.key !== LAND_REDIRECT_ID_KEY,
        );
      }
    }
  },
});
</script>

<template>
  <n-modal
    :auto-focus="false"
    v-model:show="show_model"
    @after-enter="on_modal_enter"
  >
    <n-card
      style="width: 600px"
      :title="t('misc.docker_run.title', { image: props.image_name })"
      :bordered="false"
      size="small"
      role="dialog"
      aria-modal="true"
    >
      <n-form v-if="formModel" :model="formModel" label-width="120px">
        <n-grid :cols="6" :x-gap="12">
          <n-form-item-gi
            :span="3"
            :label="t('misc.docker_run.container_name')"
            path="containerName"
          >
            <n-input
              v-model:value="formModel.container_name"
              :placeholder="t('misc.docker_run.container_name_placeholder')"
            />
          </n-form-item-gi>

          <n-form-item-gi
            :offset="1"
            :span="2"
            :label="t('misc.docker_run.flow_egress')"
            path="imageName"
          >
            <n-switch v-model:value="has_edge_label"> </n-switch>
          </n-form-item-gi>
          <n-form-item-gi
            :span="6"
            :label="t('misc.docker_run.restart_policy')"
            path="containerName"
          >
            <n-input-group>
              <n-select
                v-model:value="formModel.restart"
                :options="restrt_options"
              />
              <n-input-number
                v-if="
                  formModel.restart ===
                  DockerRestartPolicy.ON_FAILURE_WITH_MAX_RETRIES
                "
                v-model:value="formModel.restart_max_retries"
                placeholder=""
              />
            </n-input-group>
          </n-form-item-gi>

          <n-form-item-gi
            :span="6"
            :label="t('misc.docker_run.entrypoint')"
            path="containerName"
          >
            <n-input
              v-model:value="formModel.entrypoint"
              :placeholder="t('misc.docker_run.entrypoint_placeholder')"
            />
          </n-form-item-gi>
          <!-- <n-form-item-gi label="entrypoint params" path="containerName">
          <n-input
            v-model:value="formModel.params"
            placeholder="请输入entrypoint params (可选)"
          />
        </n-form-item-gi> -->
          <n-form-item-gi
            :span="6"
            :label="t('misc.docker_run.port_mapping')"
            path="ports"
          >
            <n-dynamic-input
              v-model:value="formModel.ports"
              preset="pair"
              separator=":"
              :key-placeholder="t('misc.docker_run.host_port')"
              :value-placeholder="t('misc.docker_run.container_port')"
            />
          </n-form-item-gi>
          <n-form-item-gi
            :span="6"
            :label="t('misc.docker_run.env_vars')"
            path="environment"
          >
            <n-dynamic-input
              v-model:value="formModel.environment"
              preset="pair"
              separator=":"
              :key-placeholder="t('misc.docker_run.env_name')"
              :value-placeholder="t('misc.docker_run.env_value')"
            />
          </n-form-item-gi>
          <n-form-item-gi
            :span="6"
            :label="t('misc.docker_run.volume_mapping')"
            path="volumes"
          >
            <n-dynamic-input
              v-model:value="formModel.volumes"
              preset="pair"
              separator=":"
              :key-placeholder="t('misc.docker_run.host_dir')"
              :value-placeholder="t('misc.docker_run.container_dir')"
            />
          </n-form-item-gi>
          <!-- <n-form-item-gi label-style="width: 100%;" content-style="width: 100%;">
          <template #label>
            <n-flex
              align="center"
              justify="space-between"
              :wrap="false"
              @click.stop
            >
              <n-flex> 标签 </n-flex>
              <n-flex>
                <button
                  style="
                    width: 0;
                    height: 0;
                    overflow: hidden;
                    opacity: 0;
                    position: absolute;
                  "
                ></button>
                <n-switch v-model:value="has_edge_label">
                  <template #checked> 已添加 edge 标签 </template>
                  <template #unchecked> 未添加 edge 标签 </template>
                </n-switch>
              </n-flex>
            </n-flex>
          </template>
          <n-flex style="flex: 1" vertical>
            <n-dynamic-input
              v-model:value="formModel.labels"
              preset="pair"
              separator=":"
              key-placeholder="key"
              value-placeholder="value"
            />
          </n-flex>
        </n-form-item-gi> -->
        </n-grid>
      </n-form>
      <template #footer>
        <n-flex justify="end">
          <n-button
            :loading="save_loading"
            round
            type="primary"
            @click="save_config"
          >
            {{ t("misc.docker_run.create") }}
          </n-button>
        </n-flex>
      </template>
    </n-card>
  </n-modal>
</template>
