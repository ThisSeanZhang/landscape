<script setup lang="ts">
import IntervalFetch from "@/components/head/IntervalFetch.vue";
import LanguageSetting from "@/components/head/LanguageSetting.vue";

import LandscapeSiderBar from "@/views/LandscapeSiderBar.vue";
</script>
<template>
  <div style="flex: 1">
    <n-layout position="absolute" has-sider>
      <LandscapeSiderBar />
      <n-layout>
        <n-layout-header
          style="height: 30px; padding: 0 10px; display: flex"
          bordered
        >
          <n-flex style="flex: 1" justify="space-between" align="center">
            <n-flex>/</n-flex>
            <n-flex>
              <PresentationMode></PresentationMode>
              <LanguageSetting />
              <IntervalFetch />
            </n-flex>
          </n-flex>
        </n-layout-header>
        <n-layout
          :native-scrollbar="false"
          position="absolute"
          style="
            top: 40px;
            right: 0px;
            bottom: 0px;
            display: flex;
            padding-left: 25px;
          "
          content-style="flex:1; display: flex; padding-right: 15px; height: 100%;"
          content-class="main-body"
        >
          <RouterView />
        </n-layout>
        <!-- <n-layout-footer
          position="absolute"
          style="height: 30px"
          content-style="dispaly: flex; height: 30px"
        >
          <n-flex style="height: 30px" align="center">
            <CopyRight :icon="true"></CopyRight>
          </n-flex>
        </n-layout-footer> -->
      </n-layout>
    </n-layout>
  </div>
</template>
