<script setup lang="ts">
import { computed } from "vue";
import { useI18n } from "vue-i18n";
import { VeyTable } from "@/components/ui";

const props = defineProps<{
  protocol: string;
  config: Record<string, unknown> | null;
}>();

const { t } = useI18n();

const commandResponseRows = computed(() => {
  const responses = props.config?.command_responses;
  if (Array.isArray(responses)) return responses;
  if (!responses || typeof responses !== "object") return [];
  return Object.entries(responses).map(([command, response]) => ({
    command,
    response: String(response),
  }));
});

const directoryEntryRows = computed(() => {
  const entries = props.config?.entries;
  return Array.isArray(entries) ? entries : [];
});

const dnsRecordRows = computed(() => {
  const records = props.config?.records;
  if (!records || typeof records !== "object" || Array.isArray(records)) {
    return [];
  }
  return Object.entries(records).map(([name, address]) => ({
    name,
    address: String(address),
  }));
});

const probeMapRows = computed(() => {
  const path = props.protocol === "memcached" ? "stats" : "oids";
  if (!["memcached", "snmp"].includes(props.protocol)) return [];
  const values = props.config?.[path];
  if (!values || typeof values !== "object" || Array.isArray(values)) {
    return [];
  }
  return Object.entries(values).map(([key, value]) => ({
    key,
    value: String(value),
  }));
});
</script>

<template>
  <div
    v-if="commandResponseRows.length"
    class="section-card"
    data-slot="command-response-detail"
  >
    <h4>{{ t("app.simulation.rules.detailSections.commandResponses") }}</h4>
    <div class="table-scroll-container">
      <VeyTable
        :data="commandResponseRows"
        :columns="[
          {
            label: t('common.index'),
            width: 70,
            align: 'center',
            slot: 'index',
          },
          {
            prop: 'command',
            label: t('app.simulation.rules.fields.command'),
            minWidth: 180,
          },
          {
            prop: 'response',
            label: t('app.simulation.rules.fields.response'),
            minWidth: 280,
          },
        ]"
        border
      >
        <template #index="{ index }">{{ index + 1 }}</template>
      </VeyTable>
    </div>
  </div>

  <div
    v-if="protocol === 'ldap' && directoryEntryRows.length"
    class="section-card"
    data-slot="directory-entry-detail"
  >
    <h4>{{ t("app.simulation.rules.detailSections.directoryEntries") }}</h4>
    <div class="table-scroll-container">
      <VeyTable
        :data="directoryEntryRows"
        :columns="[
          {
            label: t('common.index'),
            width: 70,
            align: 'center',
            slot: 'index',
          },
          {
            prop: 'dn',
            label: t('app.simulation.rules.fields.dn'),
            minWidth: 300,
          },
          {
            prop: 'objectClass',
            label: t('app.simulation.rules.fields.objectClass'),
            minWidth: 180,
          },
        ]"
        border
      >
        <template #index="{ index }">{{ index + 1 }}</template>
      </VeyTable>
    </div>
  </div>

  <div
    v-if="protocol === 'dns' && dnsRecordRows.length"
    class="section-card"
    data-slot="dns-record-detail"
  >
    <h4>{{ t("app.simulation.rules.detailSections.dnsRecords") }}</h4>
    <div class="table-scroll-container">
      <VeyTable
        :data="dnsRecordRows"
        :columns="[
          {
            label: t('common.index'),
            width: 70,
            align: 'center',
            slot: 'index',
          },
          {
            prop: 'name',
            label: t('app.simulation.rules.dnsRecords.key'),
            minWidth: 260,
          },
          {
            prop: 'address',
            label: t('app.simulation.rules.dnsRecords.value'),
            minWidth: 180,
          },
        ]"
        border
      >
        <template #index="{ index }">{{ index + 1 }}</template>
      </VeyTable>
    </div>
  </div>

  <div
    v-if="probeMapRows.length"
    class="section-card"
    data-slot="probe-map-detail"
  >
    <h4>
      {{
        t(
          `app.simulation.rules.detailSections.${
            protocol === "memcached" ? "memcachedStats" : "snmpOids"
          }`,
        )
      }}
    </h4>
    <div class="table-scroll-container">
      <VeyTable
        :data="probeMapRows"
        :columns="[
          {
            label: t('common.index'),
            width: 70,
            align: 'center',
            slot: 'index',
          },
          {
            prop: 'key',
            label: t('app.simulation.rules.fields.key'),
            minWidth: 260,
          },
          {
            prop: 'value',
            label: t('app.simulation.rules.fields.value'),
            minWidth: 220,
          },
        ]"
        border
      >
        <template #index="{ index }">{{ index + 1 }}</template>
      </VeyTable>
    </div>
  </div>
</template>

<style scoped>
.section-card h4 {
  margin: 0 0 12px;
  font-size: 14px;
  color: var(--vdl-primary);
  font-weight: 600;
}

.table-scroll-container {
  max-height: 220px;
  overflow-y: auto;
  border-radius: var(--vdl-radius-md);
  border: 1px solid var(--vdl-border-subtle);
}
</style>
