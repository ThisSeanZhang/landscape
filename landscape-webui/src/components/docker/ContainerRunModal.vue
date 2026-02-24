<script setup lang="ts">
import { run_cmd } from "@/api/docker";
import { KeyValuePair } from "@/lib/common";
import { LAND_REDIRECT_ID_KEY } from "@/lib/docker";
import { DockerCmd } from "@landscape-router/types/api/schemas";
import { useDockerStore } from "@/stores/status_docker";
import { useNotification } from "naive-ui";
import { computed, ref } from "vue";

const show_model = defineModel<boolean>("show", { required: true });

const props = defineProps<{
  image_name: string;
}>();

const emit = defineEmits(["refresh"]);

const dockerStore = useDockerStore();
const notification = useNotification();

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
    label: "不自动重启",
    value: DockerRestartPolicy.NO,
  },
  {
    label: "失败时自动重启",
    value: DockerRestartPolicy.ON_FAILURE,
  },
  {
    label: "失败时自动重启（带最大重试次数）",
    value: DockerRestartPolicy.ON_FAILURE_WITH_MAX_RETRIES,
  },
  {
    label: "总是自动重启",
    value: DockerRestartPolicy.ALWAYS,
  },
  {
    label: "除非手动停止，否则自动重启",
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
      :title="`运行镜像: ${props.image_name}`"
      :bordered="false"
      size="small"
      role="dialog"
      aria-modal="true"
    >
      <n-form v-if="formModel" :model="formModel" label-width="120px">
        <n-grid :cols="6" :x-gap="12">
          <n-form-item-gi :span="3" label="容器名称" path="containerName">
            <n-input
              v-model:value="formModel.container_name"
              placeholder="请输入容器名称 (可选)"
            />
          </n-form-item-gi>

          <n-form-item-gi
            :offset="1"
            :span="2"
            label="用作 Flow 出口"
            path="imageName"
          >
            <n-switch v-model:value="has_edge_label"> </n-switch>
          </n-form-item-gi>
          <n-form-item-gi :span="6" label="重启策略" path="containerName">
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

          <n-form-item-gi :span="6" label="entrypoint" path="containerName">
            <n-input
              v-model:value="formModel.entrypoint"
              placeholder="请输入 entrypoint (可选)"
            />
          </n-form-item-gi>
          <!-- <n-form-item-gi label="entrypoint params" path="containerName">
          <n-input
            v-model:value="formModel.params"
            placeholder="请输入entrypoint params (可选)"
          />
        </n-form-item-gi> -->
          <n-form-item-gi :span="6" label="端口映射" path="ports">
            <n-dynamic-input
              v-model:value="formModel.ports"
              preset="pair"
              separator=":"
              key-placeholder="主机端口"
              value-placeholder="容器端口"
            />
          </n-form-item-gi>
          <n-form-item-gi :span="6" label="环境变量" path="environment">
            <n-dynamic-input
              v-model:value="formModel.environment"
              preset="pair"
              separator=":"
              key-placeholder="变量名"
              value-placeholder="变量值"
            />
          </n-form-item-gi>
          <n-form-item-gi :span="6" label="卷映射" path="volumes">
            <n-dynamic-input
              v-model:value="formModel.volumes"
              preset="pair"
              separator=":"
              key-placeholder="主机目录"
              value-placeholder="容器目录"
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
            创建容器
          </n-button>
        </n-flex>
      </template>
    </n-card>
  </n-modal>
</template>
