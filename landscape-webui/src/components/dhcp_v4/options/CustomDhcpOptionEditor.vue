<script setup lang="ts">
import { computed } from "vue";
import DHCPOptionTFTPServer from "./DHCPOptionTFTPServer.vue";
import DHCPOptionBootfileName from "./DHCPOptionBootfileName.vue";
import DHCPOptionVendorExtensions from "./DHCPOptionVendorExtensions.vue";
import DHCPOptionRelayAgentInfo from "./DHCPOptionRelayAgentInfo.vue";
import DHCPOptionDnr from "./DHCPOptionDnr.vue";
import type {
  CustomDhcpOption,
  DhcpV4DnrOptionConfig,
  RelayAgentInfo,
} from "./types";

const model = defineModel<CustomDhcpOption[]>({ required: true });

const typeOptions = [
  { label: "TFTP Server Name (66)", value: "TFTPServerName" as const },
  { label: "Bootfile Name (67)", value: "BootfileName" as const },
  { label: "Vendor Extensions (43)", value: "VendorExtensions" as const },
  { label: "Relay Agent Info (82)", value: "RelayAgentInformation" as const },
  { label: "Encrypted DNS Discovery (162)", value: "Dnr" as const },
];

const duplicateKeys = computed(() => {
  const seen = new Set<string>();
  const dups = new Set<string>();
  for (const opt of model.value) {
    const key = getVariant(opt);
    if (!key) continue;
    if (seen.has(key)) dups.add(key);
    else seen.add(key);
  }
  return dups;
});

const hasDuplicate = computed(() => duplicateKeys.value.size > 0);
const validationErrors = computed(() => {
  const errors: string[] = [];
  for (const opt of model.value) {
    const key = getVariant(opt);
    const value = (opt as Record<string, unknown>)[key];

    if (key === "TFTPServerName" || key === "BootfileName") {
      if (typeof value !== "string" || value.length === 0) {
        errors.push(`${key} must not be empty`);
      } else if (!/^[\x00-\x7F]+$/.test(value)) {
        errors.push(`${key} must contain only ASCII characters`);
      } else if (value.length > 255) {
        errors.push(`${key} must be 255 bytes or less`);
      }
      continue;
    }

    if (key === "VendorExtensions") {
      if (typeof value !== "string" || value.length === 0) {
        errors.push("VendorExtensions must not be empty");
      } else if (!/^[\da-fA-F]+$/.test(value)) {
        errors.push("VendorExtensions must be a hex string");
      } else if (value.length % 2 !== 0) {
        errors.push("VendorExtensions hex string must have even length");
      } else if (value.length > 510) {
        errors.push("VendorExtensions must be 255 bytes or less");
      }
      continue;
    }

    if (key === "RelayAgentInformation") {
      if (value === null || typeof value !== "object" || Array.isArray(value)) {
        errors.push("RelayAgentInformation must be a JSON object");
      } else if (Object.keys(value).length === 0) {
        errors.push("RelayAgentInformation must not be empty");
      }
      continue;
    }

    if (key === "Dnr") {
      if (value === null || typeof value !== "object" || Array.isArray(value)) {
        errors.push("DNR must be a JSON object");
      } else if (!isValidDnr(value as DhcpV4DnrOptionConfig)) {
        errors.push("DNR custom values are invalid");
      }
      continue;
    }

    errors.push("Unknown DHCP option type");
  }
  return errors;
});
const hasInvalid = computed(() => validationErrors.value.length > 0);

defineExpose({ hasDuplicate, hasInvalid, validationErrors });

function isDuplicate(opt: CustomDhcpOption): boolean {
  return duplicateKeys.value.has(getVariant(opt));
}

function isInvalid(opt: CustomDhcpOption): boolean {
  const key = getVariant(opt);
  const value = (opt as Record<string, unknown>)[key];

  if (key === "TFTPServerName" || key === "BootfileName") {
    return (
      typeof value !== "string" ||
      value.length === 0 ||
      !/^[\x00-\x7F]+$/.test(value) ||
      value.length > 255
    );
  }
  if (key === "VendorExtensions") {
    return (
      typeof value !== "string" ||
      value.length === 0 ||
      !/^[\da-fA-F]+$/.test(value) ||
      value.length % 2 !== 0 ||
      value.length > 510
    );
  }
  if (key === "RelayAgentInformation") {
    return (
      value === null ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      Object.keys(value).length === 0
    );
  }
  if (key === "Dnr") {
    return (
      value === null ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      !isValidDnr(value as DhcpV4DnrOptionConfig)
    );
  }
  return true;
}

function onCreate(): CustomDhcpOption {
  return { TFTPServerName: "" };
}

function getDefaultValue(
  newType: string,
): string | RelayAgentInfo | DhcpV4DnrOptionConfig {
  if (newType === "RelayAgentInformation") return {};
  if (newType === "Dnr") return { mode: "local" };
  return "";
}

function getVariant(opt: CustomDhcpOption): string {
  return Object.keys(opt)[0];
}

function onChangeType(opt: CustomDhcpOption, newType: string): void {
  const oldKey = getVariant(opt);
  if (oldKey === newType) return;
  delete (opt as Record<string, unknown>)[oldKey];
  (opt as Record<string, unknown>)[newType as string] =
    getDefaultValue(newType);
}

function isValidDnr(value: DhcpV4DnrOptionConfig): boolean {
  if (value.mode === "local") return true;
  if (value.mode !== "custom") return false;
  if (
    value.port !== undefined &&
    value.port !== null &&
    (value.port < 1 || value.port > 65535)
  ) {
    return false;
  }
  if (value.domains?.some((domain) => !isValidDomain(domain))) return false;
  if (value.doh_path && !isValidDohPath(value.doh_path)) return false;
  const ips = value.ips ?? [];
  return ips.every(isValidDnrIpv4);
}

function isValidDomain(domain: string): boolean {
  const normalized = domain.trim().replace(/\.+$/, "").toLowerCase();
  if (
    !normalized ||
    normalized.length > 253 ||
    normalized.includes("*") ||
    !/^[\x00-\x7F]+$/.test(normalized)
  ) {
    return false;
  }
  return normalized
    .split(".")
    .every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label));
}

function isValidDohPath(path: string): boolean {
  const value = path.trim();
  if (
    !value ||
    !value.startsWith("/") ||
    !/^[\x00-\x7F]+$/.test(value) ||
    value.includes("#")
  )
    return false;
  const tokens = ["{?dns}", "{&dns}", "{dns}"];
  const present = tokens.filter((token) => value.includes(token));
  if (present.length > 1) return false;
  const token = present[0];
  if (token) {
    if (value.indexOf(token) !== value.lastIndexOf(token)) return false;
    const withoutToken = value.replace(token, "");
    if (withoutToken.includes("{") || withoutToken.includes("}")) return false;
    const beforeTemplate = value.slice(0, value.indexOf(token));
    if (token === "{?dns}" && beforeTemplate.includes("?")) return false;
    if (token === "{&dns}" && !beforeTemplate.includes("?")) return false;
    return true;
  }
  return !value.includes("?") && !value.includes("#");
}

function isValidDnrIpv4(ip: string): boolean {
  const parts = ip.split(".");
  if (parts.length !== 4) return false;
  const octets = parts.map((part) => {
    if (!/^\d{1,3}$/.test(part)) return Number.NaN;
    return Number(part);
  });
  if (
    octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)
  )
    return false;
  const [first, second, third, fourth] = octets;
  if (first === 0 || first === 127 || first >= 224) return false;
  if (first === 255 && second === 255 && third === 255 && fourth === 255)
    return false;
  return true;
}
</script>

<template>
  <n-dynamic-input
    v-model:value="model"
    :on-create="onCreate"
    :min="0"
    show-sort-button
  >
    <template #default="{ value }">
      <n-flex :size="8" align="center">
        <n-select
          :value="getVariant(value)"
          :options="typeOptions"
          :status="isDuplicate(value) || isInvalid(value) ? 'error' : undefined"
          style="width: 200px; flex-shrink: 0"
          @update:value="(v: string) => onChangeType(value, v)"
        />
        <div style="flex: 1">
          <DHCPOptionTFTPServer
            v-if="getVariant(value) === 'TFTPServerName'"
            v-model="value.TFTPServerName"
          />
          <DHCPOptionBootfileName
            v-else-if="getVariant(value) === 'BootfileName'"
            v-model="value.BootfileName"
          />
          <DHCPOptionVendorExtensions
            v-else-if="getVariant(value) === 'VendorExtensions'"
            v-model="value.VendorExtensions"
          />
          <DHCPOptionRelayAgentInfo
            v-else-if="getVariant(value) === 'RelayAgentInformation'"
            v-model="value.RelayAgentInformation"
          />
          <DHCPOptionDnr
            v-else-if="getVariant(value) === 'Dnr'"
            v-model="value.Dnr"
          />
        </div>
      </n-flex>
    </template>
  </n-dynamic-input>
</template>
