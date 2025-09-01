<script setup lang="ts">
import { delete_static_nat_mapping } from "@/api/static_nat_mapping";
import { StaticNatMappingConfig } from "@/rust_bindings/common/nat";
import { computed, ref } from "vue";
import { DotMark } from "@vicons/carbon";

const rule = defineModel<StaticNatMappingConfig>("rule", { required: true });

const show_edit_modal = ref(false);

const emit = defineEmits(["refresh"]);

async function del() {
  if (rule.value.id !== null) {
    await delete_static_nat_mapping(rule.value.id);
    emit("refresh");
  }
}

// const title = computed(() => {
//   const wan_iface_name = rule.value.wan_iface_name
//     ? `${rule.value.wan_iface_name}:`
//     : "any wan";

//   const target_str =
//     rule.value.lan_ip === "0.0.0.0" || rule.value.lan_ip === "::"
//       ? `Route:${rule.value.lan_port}`
//       : `${rule.value.lan_ip}:${rule.value.lan_port}`;
//   return `${wan_iface_name}:${rule.value.wan_port} => ${target_str}`;
// });
</script>
<template>
  <n-flex>
    <n-card size="small" style="flex: 1; min-height: 150px">
      <template #header>
        <StatusTitle :enable="rule.enable" :remark="rule.remark"></StatusTitle>
      </template>

      <!-- {{ rule }} -->

      <n-descriptions
        size="small"
        bordered
        label-placement="left"
        label-align="center"
        label-style="width: 85px"
        :column="2"
      >
        <!-- <n-descriptions-item label="启用">
          <n-tag :bordered="false" :type="rule.enable ? 'success' : ''">
            {{ rule.enable }}
          </n-tag>
        </n-descriptions-item> -->

        <n-descriptions-item label="IPv4 协议" content-style="width:120px">
          <n-flex>
            <n-tag
              :bordered="false"
              v-for="e in rule.ipv4_l4_protocol"
              :type="e === 6 ? 'success' : 'info'"
            >
              {{ e === 6 ? "TCP" : "UDP" }}
            </n-tag>
          </n-flex>
        </n-descriptions-item>

        <n-descriptions-item label="IPv4 映射">
          {{
            rule.lan_ipv4
              ? `${rule.wan_port} => ${rule.lan_ipv4}:${rule.lan_port}`
              : "无映射"
          }}
        </n-descriptions-item>

        <n-descriptions-item label="IPv6 协议" content-style="width:120px">
          <n-flex>
            <n-tag
              :bordered="false"
              v-for="e in rule.ipv6_l4_protocol"
              :type="e === 6 ? 'success' : 'info'"
            >
              {{ e === 6 ? "TCP" : "UDP" }}
            </n-tag>
          </n-flex>
        </n-descriptions-item>

        <n-descriptions-item label="创建时间">
          <n-time :time="rule.update_at" format="yyyy-MM-dd hh:mm:ss" />
        </n-descriptions-item>

        <n-descriptions-item label="IPv6 映射" span="2">
          {{
            rule.lan_ipv6
              ? `${rule.wan_port} => [${rule.lan_ipv6}]:${rule.lan_port}`
              : "无映射"
          }}
        </n-descriptions-item>
        <!-- <n-descriptions-item label="备注">
          {{ rule.remark === "" ? "无备注" : rule.remark }}
        </n-descriptions-item> -->
      </n-descriptions>
      <template #header-extra>
        <n-flex>
          <n-button
            size="small"
            type="warning"
            secondary
            @click="show_edit_modal = true"
          >
            编辑
          </n-button>

          <n-popconfirm @positive-click="del()">
            <template #trigger>
              <n-button size="small" type="error" secondary @click="">
                删除
              </n-button>
            </template>
            确定删除吗
          </n-popconfirm>
        </n-flex>
      </template>
    </n-card>
    <MappingEditModal
      @refresh="emit('refresh')"
      :rule_id="rule.id"
      v-model:show="show_edit_modal"
    >
    </MappingEditModal>
  </n-flex>
</template>
