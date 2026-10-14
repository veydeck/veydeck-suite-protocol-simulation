<script setup lang="ts">
import { computed } from "vue";
import { useI18n } from "vue-i18n";
import { VeyTable, VeyTag } from "@/components/ui";

const props = defineProps<{
  protocol: string;
  config: Record<string, unknown> | null;
}>();

const { t } = useI18n();

const mailCredentialRows = computed(
  () =>
    (props.config?.credentials as Array<Record<string, unknown>> | undefined) ||
    [],
);

const mailCapabilityRows = computed(() =>
  ((props.config?.capabilities as string[] | undefined) || []).map(
    (capability) => ({
      capability,
    }),
  ),
);

const mailMessageRows = computed(() => {
  if (props.protocol === "imap") {
    const mailboxes =
      (props.config?.mailboxes as
        | Record<string, Array<Record<string, unknown>>>
        | undefined) || {};
    return Object.entries(mailboxes).flatMap(([mailbox, messages]) =>
      messages.map((message) => ({
        mailbox,
        ...message,
      })),
    );
  }
  return (
    (props.config?.messages as Array<Record<string, unknown>> | undefined) || []
  );
});

const mailCommandRows = computed(
  () =>
    (props.config?.custom_responses as
      | Array<Record<string, unknown>>
      | undefined) || [],
);
</script>

<template>
  <div class="section-card">
    <h4>{{ t("app.simulation.rules.detailSections.mailCredentials") }}</h4>
    <div class="table-scroll-container">
      <VeyTable
        :data="mailCredentialRows"
        :columns="[
          {
            label: t('common.index'),
            width: 70,
            align: 'center',
            slot: 'index',
          },
          { prop: 'username', label: 'Username', minWidth: 180 },
          { prop: 'display_name', label: 'Display Name', minWidth: 180 },
        ]"
        border
      >
        <template #index="{ index }">
          {{ index + 1 }}
        </template>
        <template #empty>
          <div class="empty-placeholder">{{ t("common.none") }}</div>
        </template>
      </VeyTable>
    </div>
  </div>

  <div class="section-card">
    <h4>{{ t("app.simulation.rules.detailSections.mailCapabilities") }}</h4>
    <div class="table-scroll-container">
      <VeyTable
        :data="mailCapabilityRows"
        :columns="[
          {
            label: t('common.index'),
            width: 70,
            align: 'center',
            slot: 'index',
          },
          { prop: 'capability', label: 'Capability', minWidth: 260 },
        ]"
        border
      >
        <template #index="{ index }">
          {{ index + 1 }}
        </template>
        <template #empty>
          <div class="empty-placeholder">{{ t("common.none") }}</div>
        </template>
      </VeyTable>
    </div>
  </div>

  <div v-if="protocol !== 'smtp'" class="section-card">
    <h4>{{ t("app.simulation.rules.detailSections.mailMessages") }}</h4>
    <div class="table-scroll-container">
      <VeyTable
        :data="mailMessageRows"
        :columns="[
          {
            label: t('common.index'),
            width: 70,
            align: 'center',
            slot: 'index',
          },
          { prop: 'mailbox', label: 'Mailbox', width: 120 },
          { prop: 'uid', label: 'UID', width: 120 },
          { prop: 'from', label: 'From', minWidth: 180 },
          { prop: 'subject', label: 'Subject', minWidth: 220 },
        ]"
        border
      >
        <template #index="{ index }">
          {{ index + 1 }}
        </template>
        <template #empty>
          <div class="empty-placeholder">{{ t("common.none") }}</div>
        </template>
      </VeyTable>
    </div>
  </div>

  <div class="section-card">
    <h4>{{ t("app.simulation.rules.detailSections.mailCommands") }}</h4>
    <div class="table-scroll-container">
      <VeyTable
        :data="mailCommandRows"
        :columns="[
          {
            label: t('common.index'),
            width: 70,
            align: 'center',
            slot: 'index',
          },
          { prop: 'command', label: 'Command', width: 140 },
          { prop: 'event_type', label: 'Event', width: 150, slot: 'event' },
          { prop: 'response', label: 'Response', minWidth: 260 },
        ]"
        border
      >
        <template #index="{ index }">
          {{ index + 1 }}
        </template>
        <template #event="{ row }">
          <VeyTag
            :type="row.event_type === 'exploit_attempt' ? 'danger' : 'info'"
            size="small"
          >
            {{ row.event_type || `${protocol}_command` }}
          </VeyTag>
        </template>
        <template #empty>
          <div class="empty-placeholder">{{ t("common.none") }}</div>
        </template>
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

.empty-placeholder {
  text-align: center;
  padding: 32px 16px;
  color: var(--vdl-text-subtle);
  font-size: 13px;
}
</style>
