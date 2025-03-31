<script setup lang="ts">
import { run_cmd } from "@/api/docker";
import { KeyValuePair } from "@/lib/common";
import { DockerCmd } from "@/lib/docker";
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
const formModel = ref(
  new DockerCmd({
    image_name: props.image_name,
  })
);

async function on_modal_enter() {
  formModel.value = new DockerCmd({
    image_name: props.image_name,
  });
}
async function save_config() {
  await run_cmd(formModel.value);
  dockerStore.UPDATE_INFO();
}

const id_key = "ld_red_id";

function add_redirect_id() {
  if (formModel.value.labels) {
    for (const label of formModel.value.labels) {
      if (label.key === id_key) {
        // 提示
        notification.info({
          content: "已经存在标签了",
          duration: 2500,
          keepAliveOnHover: true,
        });
        break;
      }
    }
  }
  formModel.value.labels = [
    {
      key: id_key,
      value: "",
    },
  ];
}

const show_add_redirect_id_btn = computed(() => {
  for (const label of formModel.value.labels) {
    if (label.key === id_key) {
      return true;
    }
  }

  return false;
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
      <n-form :model="formModel" label-width="120px">
        <n-form-item label="镜像名称" path="imageName">
          <n-input
            :disabled="true"
            v-model:value="formModel.image_name"
            placeholder="请输入镜像名称"
          />
        </n-form-item>
        <n-form-item label="容器名称" path="containerName">
          <n-input
            v-model:value="formModel.container_name"
            placeholder="请输入容器名称 (可选)"
          />
        </n-form-item>
        <n-form-item label="端口映射" path="ports">
          <n-dynamic-input
            v-model:value="formModel.ports"
            preset="pair"
            separator=":"
            key-placeholder="主机端口"
            value-placeholder="容器端口"
          />
        </n-form-item>
        <n-form-item label="环境变量" path="environment">
          <n-dynamic-input
            v-model:value="formModel.environment"
            preset="pair"
            separator=":"
            key-placeholder="变量名"
            value-placeholder="变量值"
          />
        </n-form-item>
        <n-form-item label="卷映射" path="volumes">
          <n-dynamic-input
            v-model:value="formModel.volumes"
            preset="pair"
            separator=":"
            key-placeholder="主机目录"
            value-placeholder="容器目录"
          />
        </n-form-item>
        <n-form-item label="标签">
          <n-flex style="flex: 1" vertical>
            <n-button
              :disabled="show_add_redirect_id_btn"
              @click="add_redirect_id"
              >添加处理转发 ID
            </n-button>
            <n-dynamic-input
              v-model:value="formModel.labels"
              preset="pair"
              separator=":"
              key-placeholder="key"
              value-placeholder="value"
            />
          </n-flex>
        </n-form-item>
      </n-form>
      <template #footer>
        <n-flex justify="end">
          <n-button round type="primary" @click="save_config"> 更新 </n-button>
        </n-flex>
      </template>
    </n-card>
  </n-modal>
</template>
