<script setup lang="ts">
import { ref } from "vue";
import WanRuleEditModal from "./WanRuleEditModal.vue";
import WanRuleCard from "./WanRuleCard.vue";
import { get_wan_ip_rules } from "@/api/flow/wanip";

interface Props {
  flow_id?: number;
}

const props = withDefaults(defineProps<Props>(), {
  flow_id: 0,
});

const show = defineModel<boolean>("show", { required: true });

const rules = ref<any>([]);
async function read_rules() {
  rules.value = await get_wan_ip_rules(props.flow_id);
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
    <n-drawer-content title="编辑 Wan 规则" closable>
      <n-flex style="height: 100%" vertical>
        <!-- <n-alert type="warning"> 规则编辑后 </n-alert> -->
        <n-button @click="show_create_modal = true">增加规则</n-button>

        <n-scrollbar>
          <n-flex vertical>
            <WanRuleCard
              @refresh="read_rules()"
              v-for="rule in rules"
              :key="rule.index"
              :rule="rule"
            >
            </WanRuleCard>
          </n-flex>
        </n-scrollbar>
      </n-flex>

      <WanRuleEditModal
        :flow_id="flow_id"
        v-model:show="show_create_modal"
        @refresh="read_rules()"
      ></WanRuleEditModal>
    </n-drawer-content>
  </n-drawer>
</template>
