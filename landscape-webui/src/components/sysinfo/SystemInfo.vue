<script setup lang="ts">
import { get_sysinfo } from "@/api/sys";
import { SysInfo } from "@/lib/sys";
import { onMounted, ref } from "vue";

const sysinfo = ref<SysInfo>({
  host_name: undefined,
  system_name: undefined,
  kernel_version: undefined,
  os_version: undefined,
  landscape_version: undefined,
  cpu_arch: undefined,
  start_at: 0,
});

const now = ref<number>(new Date().getTime());

setInterval(() => {
  now.value = new Date().getTime();
}, 1000);

onMounted(async () => {
  sysinfo.value = await get_sysinfo();
});
const ui_version = __APP_VERSION__;
</script>
<template>
  <n-card title="系统">
    <n-descriptions :column="2" label-placement="left">
      <n-descriptions-item :span="2" label="主机名称">
        {{ sysinfo.host_name }}
      </n-descriptions-item>
      <n-descriptions-item :span="2" label="系统名称">
        {{ sysinfo.system_name }}
      </n-descriptions-item>
      <n-descriptions-item :span="2" label="内核版本">
        {{ sysinfo.kernel_version }}
      </n-descriptions-item>
      <n-descriptions-item label="CPU 架构">
        {{ sysinfo.cpu_arch }}
      </n-descriptions-item>
      <n-descriptions-item label="系统版本">
        {{ sysinfo.os_version }}
      </n-descriptions-item>
      <n-descriptions-item :span="2" label="启动时间">
        <n-flex :size="[4, 4]">
          <n-time :time="sysinfo.start_at" format="yyyy-MM-dd hh:mm:ss" unix />
          (<n-time :to="now" :time="sysinfo.start_at * 1000" type="relative" />)
        </n-flex>
      </n-descriptions-item>
      <!-- <n-descriptions-item :span="2" label="运行时间">
        <n-time :to="now" :time="sysinfo.start_at * 1000" type="relative" />
      </n-descriptions-item> -->
      <n-descriptions-item :span="2" label="Landscape Router 版本">
        {{ sysinfo.landscape_version }} {{ `( UI 版本: ${ui_version} )` }}
      </n-descriptions-item>
    </n-descriptions>
  </n-card>
  <!-- <n-thing>
    <template #header> 系统基本信息 </template>
    <n-descriptions :column="1" label-placement="left">
      <n-descriptions-item label="CPU 架构">
        {{ sysinfo.cpu_arch }}
      </n-descriptions-item>
      <n-descriptions-item label="主机名称">
        {{ sysinfo.host_name }}
      </n-descriptions-item>
      <n-descriptions-item label="系统名称">
        {{ sysinfo.system_name }}
      </n-descriptions-item>
      <n-descriptions-item label="内核版本">
        {{ sysinfo.kernel_version }}
      </n-descriptions-item>
      <n-descriptions-item label="系统版本">
        {{ sysinfo.os_version }}
      </n-descriptions-item>
      <n-descriptions-item label="Landscape Router 版本">
        {{ sysinfo.landscape_version }}
      </n-descriptions-item>
    </n-descriptions>
  </n-thing> -->
</template>
