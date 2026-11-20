<script setup lang="ts">
import { computed, h, ref } from "vue";
import { NIcon, type MenuOption } from "naive-ui";
import { useI18n } from "vue-i18n";
import { useRoute, useRouter } from "vue-router";
import CopyRight from "@/components/CopyRight.vue";
import { useCapabilityStore } from "@/stores/capability";
import { navigation, type NavigationItem } from "@/router/navigation";

const route = useRoute();
const router = useRouter();
const { t } = useI18n();
const capabilityStore = useCapabilityStore();
const collapsed = ref(true);

function buildMenu(items: NavigationItem[]): MenuOption[] {
  return items.flatMap(({ name, icon, children, hideWhenUnavailable }) => {
    const options = children ? buildMenu(children) : undefined;
    const capability = children
      ? undefined
      : router.resolve({ name }).meta.capability;
    const disabled =
      typeof capability === "string" && !capabilityStore.HAS(capability);
    if (disabled && hideWhenUnavailable) return [];
    return [
      {
        key: name,
        label: t(name),
        icon: icon
          ? () => h(NIcon, null, { default: () => h(icon) })
          : undefined,
        children: options,
        disabled: options ? options.every((child) => child.disabled) : disabled,
      },
    ];
  });
}

const menuOptions = computed(() => buildMenu(navigation));
const activeMenu = computed(() => String(route.meta.activeMenu ?? route.name));
function openRoute(name: string) {
  router.push({ name });
}
</script>
<template>
  <n-layout-sider
    position="relative"
    :native-scrollbar="false"
    bordered
    collapse-mode="width"
    :collapsed-width="64"
    :width="240"
    :collapsed="collapsed"
    show-trigger="bar"
    @collapse="collapsed = true"
    @expand="collapsed = false"
  >
    <n-layout position="absolute">
      <n-layout-header
        v-if="!collapsed"
        style="height: 30px; display: flex"
        bordered
      >
        <n-flex justify="center" style="flex: 1" align="center">
          Landscape
        </n-flex>
      </n-layout-header>
      <n-layout
        :native-scrollbar="false"
        position="absolute"
        style="top: 30px; bottom: 64px"
      >
        <n-menu
          :value="activeMenu"
          @update:value="openRoute"
          :collapsed="collapsed"
          :collapsed-width="64"
          :collapsed-icon-size="22"
          :options="menuOptions"
        />
      </n-layout>
      <n-layout-footer
        bordered
        position="absolute"
        content-style="display: flex; height: 30px"
      >
        <n-flex
          style="flex: 1; height: 30px"
          :justify="collapsed ? 'center' : 'start'"
          align="center"
        >
          <CopyRight :icon="true"></CopyRight>
        </n-flex>
      </n-layout-footer>
    </n-layout>
  </n-layout-sider>
</template>
