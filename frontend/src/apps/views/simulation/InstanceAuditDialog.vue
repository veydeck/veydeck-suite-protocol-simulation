<script setup lang="ts">
import { computed, onUnmounted, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import {
  VeyButton,
  VeyCheckbox,
  VeyDialog,
  VeyLoading,
  VeyPagination,
  VeyTable,
  VeyTag,
  VeyTooltip,
} from "@/components/ui";
import type { VeyTableColumn } from "@veydeck/vue";
import {
  simulationApi,
  type SimInstance,
  type SimLog,
} from "@/api/modules/simulation";
import { formatDateTime } from "@/utils/time";

const props = defineProps<{
  visible: boolean;
  instance: SimInstance | null;
}>();

const emit = defineEmits<{
  close: [];
}>();

const { t } = useI18n();
const pageSize = 50;
const records = ref<SimLog[]>([]);
const page = ref(1);
const total = ref(0);
const loading = ref(false);
const errorMessage = ref("");
const autoRefresh = ref(false);
let refreshTimer: ReturnType<typeof setInterval> | null = null;
let requestVersion = 0;

const title = computed(() =>
  t("app.simulation.auditDialog.title", {
    name: props.instance?.ruleName || "-",
  }),
);
const totalPages = computed(() =>
  Math.max(1, Math.ceil(total.value / pageSize)),
);
const columns = computed<VeyTableColumn[]>(() => [
  { label: t("common.index"), width: 70, align: "center", slot: "index" },
  {
    label: t("app.simulation.logs.columns.time"),
    width: 180,
    align: "center",
    slot: "time",
  },
  {
    prop: "clientIp",
    label: t("app.simulation.logs.columns.clientIp"),
    width: 140,
    align: "center",
  },
  {
    prop: "clientPort",
    label: t("app.simulation.logs.columns.clientPort"),
    width: 100,
    align: "center",
  },
  {
    label: t("app.simulation.logs.columns.eventType"),
    width: 140,
    align: "center",
    slot: "type",
  },
  {
    label: t("app.simulation.logs.columns.summary"),
    minWidth: 320,
    slot: "summary",
  },
]);

/** 根据诱捕事件类型返回对应状态标签。 */
const eventTypeTag = (type: string) => {
  if (type === "exploit_attempt" || type === "auth_attempt") return "danger";
  if (type === "http_request") return "info";
  if (
    type === "redis_command" ||
    type === "ftp_command" ||
    type === "rdp_negotiation" ||
    type === "smtp_command" ||
    type === "pop3_command" ||
    type === "imap_command"
  )
    return "warning";
  return "success";
};

/** 加载当前实例的一页诱捕审计，使用版本号隔离切换实例后的迟到响应。 */
const loadAuditLogs = async (silent = false) => {
  const instanceId = props.instance?.instanceId;
  if (!props.visible || !instanceId) return;
  const version = ++requestVersion;
  if (!silent) loading.value = true;
  errorMessage.value = "";
  try {
    const response = await simulationApi.listInstanceAuditLogs(instanceId, {
      page: page.value,
      pageSize,
    });
    if (version !== requestVersion) return;
    if (!response.success || !response.data) {
      errorMessage.value =
        response.message === "simulation instance not found"
          ? t("app.simulation.auditDialog.instanceUnavailable")
          : response.message || t("app.simulation.auditDialog.loadFailed");
      records.value = [];
      total.value = 0;
      return;
    }
    records.value = response.data.records;
    total.value = response.data.total;
  } catch {
    if (version === requestVersion) {
      errorMessage.value = t("app.simulation.auditDialog.loadFailed");
      records.value = [];
      total.value = 0;
    }
  } finally {
    if (version === requestVersion && !silent) loading.value = false;
  }
};

const stopRefreshTimer = () => {
  if (refreshTimer) {
    clearInterval(refreshTimer);
    refreshTimer = null;
  }
};

const syncRefreshTimer = () => {
  stopRefreshTimer();
  if (props.visible && autoRefresh.value) {
    refreshTimer = setInterval(() => {
      if (!loading.value) void loadAuditLogs(true);
    }, 10_000);
  }
};

watch(
  () => [props.visible, props.instance?.instanceId] as const,
  ([visible]) => {
    requestVersion += 1;
    records.value = [];
    total.value = 0;
    errorMessage.value = "";
    loading.value = false;
    stopRefreshTimer();
    if (!visible) return;
    if (page.value !== 1) {
      page.value = 1;
    } else {
      void loadAuditLogs();
    }
    syncRefreshTimer();
  },
);

watch(page, () => {
  if (props.visible) void loadAuditLogs();
});

watch(autoRefresh, syncRefreshTimer);

onUnmounted(() => {
  requestVersion += 1;
  stopRefreshTimer();
});
</script>

<template>
  <VeyDialog
    :visible="visible"
    :title="title"
    width="min(1080px, 92vw)"
    @close="emit('close')"
  >
    <div class="audit-dialog" data-ui="instance-audit-dialog">
      <div class="audit-context" data-slot="header">
        <span>
          <strong>{{ t("app.simulation.auditDialog.protocol") }}</strong>
          {{ instance?.protocol?.toUpperCase() || "-" }}
        </span>
        <span>
          <strong>{{ t("app.simulation.auditDialog.listenPort") }}</strong>
          {{
            instance?.endpoints
              .map(
                (endpoint) =>
                  endpoint.hostPort + "/" + endpoint.transport.toUpperCase(),
              )
              .join(", ") || "-"
          }}
        </span>
        <span class="audit-instance-id">
          <strong>{{ t("app.simulation.auditDialog.instanceId") }}</strong>
          {{ instance?.instanceId || "-" }}
        </span>
      </div>

      <div class="audit-toolbar" data-ui="instance-audit-toolbar">
        <label class="auto-refresh-control">
          <VeyCheckbox
            :model-value="autoRefresh"
            @change="(value) => (autoRefresh = value)"
          />
          <span>{{ t("app.simulation.logs.autoRefresh") }}</span>
        </label>
        <VeyButton
          type="secondary"
          size="small"
          :disabled="loading"
          @click="loadAuditLogs()"
        >
          {{ t("app.simulation.logs.refresh") }}
        </VeyButton>
      </div>

      <div class="audit-table-region" data-slot="body">
        <div v-if="errorMessage" class="audit-error" role="alert">
          {{ errorMessage }}
        </div>
        <VeyTable
          v-else
          :data="records"
          :columns="columns"
          border
          data-ui="instance-audit-table"
        >
          <template #index="{ index }">
            {{ (page - 1) * pageSize + index + 1 }}
          </template>
          <template #time="{ row }">
            <span class="audit-time">{{ formatDateTime(row.timestamp) }}</span>
          </template>
          <template #type="{ row }">
            <VeyTag :type="eventTypeTag(row.eventType)" size="small">
              {{ row.eventType.toUpperCase() }}
            </VeyTag>
          </template>
          <template #summary="{ row }">
            <VeyTooltip :text="row.detailSummary" position="top">
              <div class="audit-summary" data-ui="audit-summary">
                {{ row.detailSummary }}
              </div>
            </VeyTooltip>
          </template>
          <template #empty>
            <div class="audit-empty">{{ t("app.simulation.logs.empty") }}</div>
          </template>
        </VeyTable>
        <VeyLoading :loading="loading" cover data-ui="instance-audit-loading" />
      </div>

      <div class="audit-footer" data-slot="footer">
        <span>{{ t("app.simulation.auditDialog.total", { total }) }}</span>
        <VeyPagination
          :current-page="page"
          :total-pages="totalPages"
          @page-change="(value) => (page = value)"
        />
      </div>
    </div>
  </VeyDialog>
</template>

<style scoped>
.audit-dialog {
  display: flex;
  height: min(68vh, 640px);
  min-height: 0;
  flex-direction: column;
  gap: var(--vdl-space-3);
}

.audit-context,
.audit-toolbar,
.audit-footer {
  display: flex;
  align-items: center;
  gap: var(--vdl-space-4);
}

.audit-context {
  flex-wrap: wrap;
  padding: var(--vdl-space-3);
  border: 1px solid var(--vdl-border-subtle);
  border-radius: var(--vdl-radius-md);
  color: var(--vdl-text-secondary);
  font-size: 13px;
}

.audit-context strong {
  margin-right: var(--vdl-space-1);
  color: var(--vdl-text-muted);
  font-weight: 500;
}

.audit-instance-id,
.audit-time {
  font-family: var(--vdl-font-mono);
}

.audit-instance-id {
  min-width: 0;
  overflow-wrap: anywhere;
}

.audit-toolbar {
  justify-content: flex-end;
}

.auto-refresh-control {
  display: inline-flex;
  align-items: center;
  gap: var(--vdl-space-2);
  color: var(--vdl-text-secondary);
  font-size: 13px;
  cursor: pointer;
}

.audit-table-region {
  position: relative;
  display: flex;
  flex: 1;
  flex-direction: column;
  min-height: 0;
  overflow: hidden;
}

.audit-table-region :deep(.vl-table-container) {
  flex: 1;
  height: auto;
  min-height: 0;
}

.audit-error,
.audit-empty {
  padding: var(--vdl-space-6) var(--vdl-space-4);
  text-align: center;
}

.audit-error {
  display: grid;
  flex: 1;
  place-items: center;
  color: var(--vdl-danger);
}

.audit-empty {
  color: var(--vdl-text-subtle);
}

.audit-time {
  color: var(--vdl-text-secondary);
  font-size: 12px;
}

.audit-summary {
  overflow: hidden;
  color: var(--vdl-text-primary);
  text-overflow: ellipsis;
  white-space: nowrap;
}

.audit-footer {
  justify-content: space-between;
  padding-top: var(--vdl-space-3);
  border-top: 1px solid var(--vdl-border-subtle);
  color: var(--vdl-text-muted);
  font-size: 12px;
}

@media (max-width: 640px) {
  .audit-context,
  .audit-footer {
    align-items: flex-start;
    flex-direction: column;
  }
}
</style>
