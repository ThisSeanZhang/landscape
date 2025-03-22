<script setup lang="ts">
import { ref } from "vue";
import FirewallRuleEditModal from "./FirewallRuleEditModal.vue";
import FirewallRuleCard from "./FirewallRuleCard.vue";
import { get_firewall_rules } from "@/api/mark";

const show = defineModel<boolean>("show", { required: true });

const rules = ref<any>([]);
async function read_rules() {
  rules.value = await get_firewall_rules();
}

const show_create_modal = ref(false);
</script>
<template>
  <n-drawer
    @after-enter="read_rules()"
    v-model:show="show"
    width="500px"
    placement="right"
  >
    <n-drawer-content title="编辑防火墙规则" closable>
      <n-flex style="height: 100%" vertical>
        <!-- <n-alert type="warning"> 规则编辑后 </n-alert> -->
        <n-button @click="show_create_modal = true">增加规则</n-button>

        <n-scrollbar>
          <n-flex vertical>
            <FirewallRuleCard
              @refresh="read_rules()"
              v-for="rule in rules"
              :key="rule.index"
              :rule="rule"
            >
            </FirewallRuleCard>
          </n-flex>
        </n-scrollbar>
      </n-flex>

      <FirewallRuleEditModal
        v-model:show="show_create_modal"
        @refresh="read_rules()"
      ></FirewallRuleEditModal>
    </n-drawer-content>
  </n-drawer>
</template>
