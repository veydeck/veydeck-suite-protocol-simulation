<script setup lang="ts">
import { computed } from "vue";
import { useI18n } from "vue-i18n";
import { VeyTable } from "@/components/ui";

const props = defineProps<{
  protocol: string;
  config: Record<string, unknown> | null;
}>();

const { t } = useI18n();

const credentialRows = computed(
  () =>
    (props.config?.credentials as Array<Record<string, unknown>> | undefined) ||
    [],
);
</script>

<template>
  <div class="section-card" data-slot="creds-detail">
    <h4>{{ t("app.simulation.rules.detailSections.weakCredentials") }}</h4>
    <div class="table-scroll-container">
      <VeyTable
        :data="credentialRows"
        :columns="[
          {
            label: t('common.index'),
            width: 70,
            align: 'center',
            slot: 'index',
          },
          { prop: 'username', label: 'Username', minWidth: 180 },
          { prop: 'password', label: 'Password', minWidth: 180 },
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
