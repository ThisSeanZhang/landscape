<script setup lang="ts">
import { onMounted, ref } from "vue";
import { get_firewall_rules } from "@/api/mark";

const rules = ref<any>([]);

async function read_rules() {
  rules.value = await get_firewall_rules();
}

onMounted(async () => {
  await read_rules();
});

const show_create_modal = ref(false);
</script>
<template>
  <n-layout :native-scrollbar="false" content-style="padding: 10px;">
    <n-flex vertical>
      <!-- <n-flex> cccc</n-flex> -->
      <n-grid x-gap="12" y-gap="10" cols="1 600:2 900:3 1200:4 1600:5">
        <n-grid-item style="display: flex">
          <n-card size="small" content-style="display:flex;">
            <n-flex style="flex: 1" justify="center" align="center">
              <n-button
                @click="show_create_modal = true"
                text
                style="font-size: 24px"
              >
                <n-icon size="200">
                  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
                    <path
                      d="M368.5 240H272v-96.5c0-8.8-7.2-16-16-16s-16 7.2-16 16V240h-96.5c-8.8 0-16 7.2-16 16 0 4.4 1.8 8.4 4.7 11.3 2.9 2.9 6.9 4.7 11.3 4.7H240v96.5c0 4.4 1.8 8.4 4.7 11.3 2.9 2.9 6.9 4.7 11.3 4.7 8.8 0 16-7.2 16-16V272h96.5c8.8 0 16-7.2 16-16s-7.2-16-16-16z"
                    />
                  </svg>
                </n-icon>
              </n-button>
            </n-flex>
          </n-card>
        </n-grid-item>
        <n-grid-item
          v-for="rule in rules"
          :key="rule.index"
          style="display: flex"
        >
          <FirewallRuleCard @refresh="read_rules()" :rule="rule">
          </FirewallRuleCard>
        </n-grid-item>
      </n-grid>
    </n-flex>
    <FirewallRuleEditModal
      v-model:show="show_create_modal"
      @refresh="read_rules()"
    >
    </FirewallRuleEditModal>
  </n-layout>
</template>
