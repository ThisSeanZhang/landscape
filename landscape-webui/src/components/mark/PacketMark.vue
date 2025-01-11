<script setup lang="ts">
import { MarkType, PacketMark } from "@/lib/dns";
import { ref } from "vue";

const mark = defineModel<PacketMark>("mark", { required: true });

const mark_type_option = [
  {
    label: "不标记",
    value: MarkType.NoMark,
  },
  {
    label: "直连",
    value: MarkType.Direct,
  },
  {
    label: "禁止连接",
    value: MarkType.Drop,
  },
  {
    label: "重定向",
    value: MarkType.Redirect,
  },
  {
    label: "禁止共享打洞",
    value: MarkType.SymmetricNat,
  },
  {
    label: "重定向至 Docker",
    value: MarkType.RedirectNetns,
  },
];
</script>

<template>
  <n-input-group>
    <n-select
      style="width: 38%"
      v-model:value="mark.t"
      :options="mark_type_option"
      placeholder="选择匹配方式"
    />
    <!-- 后续能够设置 docker 网卡 -->
    <n-input-number
      :show-button="false"
      v-if="mark.t === MarkType.Redirect"
      placeholder="重定向的网卡 index"
      v-model:value="mark.index"
      type="text"
    />
    <n-input-number
      :show-button="false"
      v-else-if="mark.t === MarkType.RedirectNetns"
      placeholder="Docker 处理的流 ID"
      v-model:value="mark.index"
      type="text"
    />
    <!-- <n-input v-else :disabled="true" placeholder="" type="text" /> -->
  </n-input-group>
</template>
