<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { VeyButton, VeyDescriptions, VeyDialog } from "@/components/ui";
import type {
  SimRule,
  SimulationFieldCapability,
  SimulationProtocolCapability,
} from "@/api/modules/simulation";
import HttpRuleDetail from "./details/HttpRuleDetail.vue";
import RedisRuleDetail from "./details/RedisRuleDetail.vue";
import MailRuleDetail from "./details/MailRuleDetail.vue";
import CredsRuleDetail from "./details/CredsRuleDetail.vue";
import ProtocolNestedRuleDetail from "./details/ProtocolNestedRuleDetail.vue";
import SimulationHtmlPreviewDialog from "./SimulationHtmlPreviewDialog.vue";

const props = defineProps<{
  visible: boolean;
  rule: SimRule | null;
  capability: SimulationProtocolCapability | null;
}>();

const emit = defineEmits<{
  close: [];
}>();

const { t, locale } = useI18n();
const isHtmlPreviewVisible = ref(false);
const previewHtml = ref("");

const parsedConfig = computed<Record<string, unknown> | null>(() => {
  if (!props.rule) return null;
  try {
    return JSON.parse(props.rule.configYaml);
  } catch {
    return null;
  }
});

const protocol = computed(() => props.rule?.protocol || "");
const isHttpRule = computed(() => protocol.value === "http");
const isRedisRule = computed(() => protocol.value === "redis");
const isMailRule = computed(() =>
  ["smtp", "pop3", "imap"].includes(protocol.value),
);
const isCredsRule = computed(() =>
  ["ssh", "ftp", "rdp", "telnet", "mysql", "postgresql", "ldap"].includes(
    protocol.value,
  ),
);

const fieldLabel = (field: SimulationFieldCapability) =>
  t(`app.simulation.rules.fields.${field.labelKey}`);

const formatFieldValue = (value: unknown) => {
  if (Array.isArray(value)) return value.join(", ");
  if (typeof value === "boolean") {
    return t(
      value
        ? "app.simulation.rules.values.enabled"
        : "app.simulation.rules.values.disabled",
    );
  }
  if (typeof value === "number") return String(value);
  if (typeof value === "string" && value.trim()) return value;
  return t("common.none");
};

const visibleProtocolFields = computed(() =>
  (props.capability?.fields ?? []).filter(
    (field) =>
      !field.secret &&
      !["credentials", "key_value"].includes(field.kind) &&
      parsedConfig.value?.[field.path] !== undefined,
  ),
);

const getRuleName = (rule?: SimRule | null) => {
  if (!rule) return "";
  return locale.value === "en" ? rule.nameEn || rule.name : rule.name;
};

const getRuleDescription = (rule?: SimRule | null) => {
  if (!rule) return "";
  return locale.value === "en"
    ? rule.descriptionEn || rule.descriptionZh || ""
    : rule.descriptionZh || "";
};

const detailItems = computed(() => {
  const baseItems = [
    {
      label: t("app.simulation.rules.fields.name"),
      value: getRuleName(props.rule),
    },
    {
      label: t("app.simulation.rules.fields.defaultPort"),
      value: props.rule?.defaultPort || t("app.simulation.rules.autoAllocate"),
    },
    {
      label: t("app.simulation.rules.fields.description"),
      value: getRuleDescription(props.rule) || t("common.none"),
    },
  ];
  const items = [
    ...baseItems,
    ...visibleProtocolFields.value.map((field) => ({
      label: fieldLabel(field),
      value: formatFieldValue(parsedConfig.value?.[field.path]),
    })),
  ];
  const representedPaths = new Set(
    visibleProtocolFields.value.map((field) => field.path),
  );

  const appendOptionalField = (path: string, labelKey: string) => {
    const value = parsedConfig.value?.[path];
    if (value === undefined || representedPaths.has(path)) return;
    items.push({
      label: t(`app.simulation.rules.fields.${labelKey}`),
      value: formatFieldValue(value),
    });
  };

  if (isMailRule.value || isRedisRule.value) {
    appendOptionalField("require_auth", "requireAuth");
  }
  if (isHttpRule.value && !representedPaths.has("server_header")) {
    items.push({
      label: t("app.simulation.rules.fields.serverHeader"),
      value: t("app.simulation.rules.systemDefaultNginx"),
    });
  }
  if (protocol.value === "ftp") {
    appendOptionalField("server_name", "serverName");
    appendOptionalField("allow_anonymous", "allowAnonymous");
  }

  return items;
});

/** 打开套件内 HTML 预览，并固定本次预览内容。 */
const openHtmlPreview = (html: string) => {
  previewHtml.value = html;
  isHtmlPreviewVisible.value = true;
};

/** 关闭 HTML 预览并清理已渲染内容。 */
const closeHtmlPreview = () => {
  isHtmlPreviewVisible.value = false;
  previewHtml.value = "";
};

watch(
  () => props.visible,
  (visible) => {
    if (!visible) closeHtmlPreview();
  },
);
</script>

<template>
  <VeyDialog
    :visible="visible && !isHtmlPreviewVisible"
    :title="t('app.simulation.rules.detailAndInteractions')"
    width="800px"
    data-ui="simulation-rule-detail-dialog"
    @close="emit('close')"
  >
    <div class="dialog-detail-content flex-column gap-layout" data-slot="body">
      <div class="section-card">
        <h4>{{ t("app.simulation.rules.basicParams") }}</h4>
        <VeyDescriptions :items="detailItems" :column="2" border />
      </div>

      <HttpRuleDetail
        v-if="isHttpRule"
        :config="parsedConfig"
        @preview="openHtmlPreview"
      />
      <RedisRuleDetail v-else-if="isRedisRule" :config="parsedConfig" />
      <MailRuleDetail
        v-else-if="isMailRule"
        :protocol="protocol"
        :config="parsedConfig"
      />
      <template v-else>
        <CredsRuleDetail
          v-if="isCredsRule"
          :protocol="protocol"
          :config="parsedConfig"
        />
        <ProtocolNestedRuleDetail :protocol="protocol" :config="parsedConfig" />
      </template>
    </div>

    <template #footer>
      <VeyButton type="secondary" @click="emit('close')">
        {{ t("app.simulation.rules.closeDetails") }}
      </VeyButton>
    </template>
  </VeyDialog>

  <SimulationHtmlPreviewDialog
    :visible="visible && isHtmlPreviewVisible"
    :html="previewHtml"
    @close="closeHtmlPreview"
  />
</template>

<style scoped>
.flex-column {
  display: flex;
  flex-direction: column;
}

.gap-layout {
  gap: var(--vdl-space-4);
}

.section-card h4 {
  margin: 0 0 12px;
  font-size: 14px;
  color: var(--vdl-primary);
  font-weight: 600;
}
</style>
