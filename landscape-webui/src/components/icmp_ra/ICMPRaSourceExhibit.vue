<script setup lang="ts">
import type { IPV6RaConfigSource } from "@landscape-router/types/api/schemas";
import { computed, ref } from "vue";
import { Edit, Delete } from "@vicons/carbon";

const source = defineModel<IPV6RaConfigSource>("source", { required: true });
const tag_type = computed(() =>
  source.value.t == "static" ? "default" : "info",
);

const emit = defineEmits(["delete", "commit"]);

function emit_delete() {
  emit("delete");
}

function emit_commit(source: IPV6RaConfigSource) {
  emit("commit", source);
}

const show_edit = ref(false);
</script>
<template>
  <n-tag :type="tag_type" :bordered="false">
    <span v-if="source.t == 'static'">
      {{
        `${source.base_prefix} @ ${source.sub_index} / ${source.sub_prefix_len}`
      }}
    </span>
    <span v-else>
      {{
        `${source.depend_iface} @ ${source.subnet_index} / ${source.prefix_len}`
      }}
    </span>

    <template #icon>
      <n-flex :size="[5, 0]">
        <n-button @click="show_edit = true" type="warning" text size="small">
          <n-icon>
            <Edit />
          </n-icon>
        </n-button>
        <n-button @click="emit_delete" type="error" text size="small">
          <n-icon>
            <Delete />
          </n-icon>
        </n-button>
      </n-flex>
    </template>

    <ICMPRaSourceEdit
      @commit="emit_commit"
      v-model:show="show_edit"
      :source="source"
    ></ICMPRaSourceEdit>
  </n-tag>
</template>
