<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch } from "vue";
import { useI18n } from "vue-i18n";
import {
  VeyButton,
  VeyTable,
  VeyTag,
  VeyInput,
  VeySelect,
  VeyLoading,
  VeyPagination,
  VeyDialog,
  VeyModal,
  VeyTooltip,
  VeyCheckbox,
  VeyActionMenu,
  VeySelectionBar,
  VeyTabs,
} from "@/components/ui";
import type { VeyTableColumn } from "@veydeck/vue";
import {
  simulationApi,
  SIMULATION_PROTOCOL_DEFAULT_PORTS,
  SIMULATION_PROTOCOL_OPTIONS,
  type SimRule,
  type SimInstance,
  type SimRulePackage,
  type SimulationProtocolCapability,
  type SimulationProtocol,
} from "@/api/modules/simulation";
import type { NodeSummaryResponse } from "@/api/modules/nodes";
import { formatDateTime } from "@/utils/time";
import { useNotificationStore } from "@/stores/notification";
import {
  registerConfirmationHandler,
  useConfirmationModalStore,
} from "@/stores/confirmation-modal";
import SimulationRuleDetailDialog from "./simulation/SimulationRuleDetailDialog.vue";
import InstanceAuditDialog from "./simulation/InstanceAuditDialog.vue";

defineProps<{
  isMaximized?: boolean;
  payload?: Record<string, unknown>;
}>();

const { t, locale } = useI18n();
const notificationStore = useNotificationStore();
const modalStore = useConfirmationModalStore();

/**
 * 根据当前多语言设置获取仿真诱捕规则的显示名称
 * @param rule 仿真规则对象
 * @returns 国际化处理后的规则名称
 */
const getRuleName = (rule?: SimRule | null) => {
  if (!rule) return "";
  return locale.value === "en" ? rule.nameEn || rule.name : rule.name;
};

/**
 * 界面核心页签导航
 * 'deployments' - 运行实例面板
 * 'rules' - 规则整编面板
 */
const activeTab = ref<"deployments" | "rules">("deployments");

/** 标准标签页使用字符串契约，对写入值做运行时收窄。 */
const activeTabModel = computed({
  get: () => activeTab.value,
  set: (value: string) => {
    if (value === "deployments" || value === "rules") activeTab.value = value;
  },
});

/** 顶部主导航由组件库统一提供材质、焦点与键盘行为。 */
const simulationTabs = computed(() => [
  { name: "deployments", label: t("app.simulation.tabs.deployments") },
  { name: "rules", label: t("app.simulation.tabs.rules") },
]);

/** 非列表业务操作的全局加载状态。 */
const isLoading = ref(false);

/** 各页签表格区域的独立加载状态，避免列表刷新遮挡整个应用。 */
const deploymentsLoading = ref(false);
const rulesLoading = ref(false);

const confirmationState = ref({
  visible: false,
  message: "",
  title: "",
  confirmText: "",
  cancelText: "",
});
let confirmationResolver: ((confirmed: boolean) => void) | null = null;

const resolveConfirmation = (confirmed: boolean) => {
  confirmationState.value.visible = false;
  confirmationResolver?.(confirmed);
  confirmationResolver = null;
};

/** 仿真诱捕规则集合 */
const rules = ref<SimRule[]>([]);

/** 主控返回的协议仿真能力清单，失败时使用前端内置兜底常量。 */
const protocolCapabilities = ref<SimulationProtocolCapability[]>(
  SIMULATION_PROTOCOL_OPTIONS.map((item) => ({
    protocol: item.value,
    label: item.label,
    defaultPort: SIMULATION_PROTOCOL_DEFAULT_PORTS[item.value],
    deployable: true,
    customRuleCreatable: true,
    eventTypes: [],
    category: "other",
    endpoints:
      item.value === "dns"
        ? [
            {
              id: "dns-tcp",
              role: "service",
              transport: "tcp",
              containerPort: 53,
              defaultHostPort: 1053,
              required: true,
            },
            {
              id: "dns-udp",
              role: "service",
              transport: "udp",
              containerPort: 53,
              defaultHostPort: 1053,
              required: true,
            },
          ]
        : [
            {
              id: "main",
              role: "service",
              transport: item.value === "snmp" ? "udp" : "tcp",
              containerPort: SIMULATION_PROTOCOL_DEFAULT_PORTS[item.value],
              defaultHostPort: SIMULATION_PROTOCOL_DEFAULT_PORTS[item.value],
              required: true,
            },
          ],
    fields: [],
  })),
);

const customRuleProtocolCapabilities = computed(() =>
  protocolCapabilities.value.filter((item) => item.customRuleCreatable),
);

/** 规则列表分页：当前页码 */
const rulesCurrentPage = ref(1);

/** 规则列表分页：根据表格可用高度动态计算的单页条数 */
const rulesPageSize = ref(10);

/** 规则表格可用区域，用于监听窗口与应用布局变化。 */
const rulesTableRegionRef = ref<HTMLElement | null>(null);

const RULES_PAGE_SIZE_MIN = 1;
const RULES_PAGE_SIZE_MAX = 100;
const RULES_TABLE_BORDER_HEIGHT = 2;
let rulesTableResizeObserver: ResizeObserver | null = null;
let rulesPageSizeFrame: number | null = null;

/** 规则整编筛选检索条件 */
const rulesFilter = ref({
  name: "",
  cve: "",
  category: "all",
  protocol: "all",
});

/** 规则类型筛选选项 */
const categoryFilterOptions = computed(() => [
  { value: "all", label: t("app.simulation.rules.filters.allCategories") },
  { value: "cve_sim", label: getCategoryLabel("cve_sim") },
  { value: "vuln_sim", label: getCategoryLabel("vuln_sim") },
  { value: "honeypot", label: getCategoryLabel("honeypot") },
  { value: "test_env", label: getCategoryLabel("test_env") },
]);

/** 协议类型筛选选项 */
const protocolFilterOptions = computed(() => [
  { value: "all", label: t("app.simulation.rules.filters.allProtocols") },
  ...protocolCapabilities.value.map((item) => ({
    value: item.protocol,
    label: item.label,
  })),
]);

/** 根据检索条件过滤后的规则列表 */
const filteredRules = computed(() => {
  return rules.value.filter((rule) => {
    // 规则名称模糊匹配 (支持中英文不区分大小写模糊匹配)
    if (rulesFilter.value.name) {
      const searchName = rulesFilter.value.name.toLowerCase();
      const matchName = rule.name.toLowerCase().includes(searchName);
      const matchNameEn = rule.nameEn
        ? rule.nameEn.toLowerCase().includes(searchName)
        : false;
      if (!matchName && !matchNameEn) return false;
    }

    // CVE 编号模糊匹配
    if (rulesFilter.value.cve) {
      const searchCve = rulesFilter.value.cve.toLowerCase();
      const matchCve = rule.cve
        ? rule.cve.toLowerCase().includes(searchCve)
        : false;
      if (!matchCve) return false;
    }

    // 规则类型精确匹配
    if (rulesFilter.value.category !== "all") {
      if (rule.category !== rulesFilter.value.category) return false;
    }

    // 协议类型精确匹配
    if (rulesFilter.value.protocol !== "all") {
      if (rule.protocol !== rulesFilter.value.protocol) return false;
    }

    return true;
  });
});

/** 计算过滤后的总页数，防止除以零，至少保持 1 页 */
const rulesTotalPages = computed(() =>
  Math.max(1, Math.ceil(filteredRules.value.length / rulesPageSize.value)),
);

const BUILTIN_RULE_MAX_ID = 999999;

/** 分页切片后的过滤规则数据集，用于表格驱动渲染 */
const pagedRules = computed(() => {
  const start = (rulesCurrentPage.value - 1) * rulesPageSize.value;
  return filteredRules.value.slice(start, start + rulesPageSize.value);
});

/**
 * 根据规则表格的实际表头、数据行与可用区域高度更新单页条数。
 * 调整容量时保留原分页首条规则所在的位置，避免窗口缩放导致跳页。
 */
const updateRulesPageSize = () => {
  rulesPageSizeFrame = null;
  const region = rulesTableRegionRef.value;
  if (!region || activeTab.value !== "rules") return;

  const headerRow = region.querySelector<HTMLElement>(".vl-table-header-row");
  const dataRow = region.querySelector<HTMLElement>(".vl-table-row");
  if (!headerRow || !dataRow) return;

  const availableHeight = region.clientHeight;
  const headerHeight = headerRow.getBoundingClientRect().height;
  const rowHeight = dataRow.getBoundingClientRect().height;
  if (availableHeight <= 0 || headerHeight <= 0 || rowHeight <= 0) return;

  const availableRowsHeight = Math.max(
    0,
    availableHeight - headerHeight - RULES_TABLE_BORDER_HEIGHT,
  );
  const nextPageSize = Math.min(
    RULES_PAGE_SIZE_MAX,
    Math.max(RULES_PAGE_SIZE_MIN, Math.floor(availableRowsHeight / rowHeight)),
  );
  if (nextPageSize === rulesPageSize.value) return;

  const firstRuleIndex = (rulesCurrentPage.value - 1) * rulesPageSize.value;
  rulesPageSize.value = nextPageSize;
  const nextTotalPages = Math.max(
    1,
    Math.ceil(filteredRules.value.length / nextPageSize),
  );
  rulesCurrentPage.value = Math.min(
    nextTotalPages,
    Math.floor(firstRuleIndex / nextPageSize) + 1,
  );
};

/** 将同一渲染帧内的多次布局变化合并为一次分页容量计算。 */
const scheduleRulesPageSizeUpdate = () => {
  if (rulesPageSizeFrame !== null) {
    cancelAnimationFrame(rulesPageSizeFrame);
  }
  rulesPageSizeFrame = requestAnimationFrame(updateRulesPageSize);
};

watch(
  rulesTableRegionRef,
  (region) => {
    rulesTableResizeObserver?.disconnect();
    rulesTableResizeObserver = null;

    if (!region) return;
    if (typeof ResizeObserver !== "undefined") {
      rulesTableResizeObserver = new ResizeObserver(
        scheduleRulesPageSizeUpdate,
      );
      rulesTableResizeObserver.observe(region);
    }
    scheduleRulesPageSizeUpdate();
  },
  { flush: "post" },
);

watch(
  () => filteredRules.value.length,
  () => {
    rulesCurrentPage.value = Math.min(
      rulesCurrentPage.value,
      rulesTotalPages.value,
    );
    scheduleRulesPageSizeUpdate();
  },
  { flush: "post" },
);

// 监听筛选条件变化，自动重置分页至第一页，避免在空页面滞留
watch(
  () => ({ ...rulesFilter.value }),
  () => {
    rulesCurrentPage.value = 1;
  },
);

/** 控制规则详情抽屉（Drawer）的打开状态 */
const isDetailDrawerOpen = ref(false);

/** 当前选中查看详情的规则对象 */
const ruleDetail = ref<SimRule | null>(null);
const ruleDetailCapability = computed(
  () =>
    protocolCapabilities.value.find(
      (item) => item.protocol === ruleDetail.value?.protocol,
    ) ?? null,
);

/** 控制部署确认弹窗（Dialog）的显示状态 */
const isDeployDialogOpen = ref(false);

/** 计划部署至目标节点的规则对象 */
const ruleToDeploy = ref<SimRule | null>(null);

/** 所有可用的边缘/本地节点概览列表 */
const nodes = ref<NodeSummaryResponse[]>([]);

/** 当前套件固定运行在本地节点。 */
const selectedNodeId = ref("local");

/** 仿真服务运行实例列表 */
const instances = ref<SimInstance[]>([]);

/** 当前打开诱捕审计对话框的实例。 */
const auditInstance = ref<SimInstance | null>(null);

/** 被勾选的多选实例 ID 集合 */
const selectedInstanceIds = ref<string[]>([]);

/** 仿真实例部署表单模型 */
const deployForm = ref({
  nodeId: "local",
  port: 8080 as number | string,
  endpointIds: [] as string[],
  ruleId: null as number | null,
  callbackUrl: "",
});

/** 是否正在提交实例部署请求，用于阻止重复部署。 */
const isDeploying = ref(false);

/** 正在执行下线操作的实例 ID，避免全局遮罩影响表格布局。 */
const undeployingInstanceIds = ref<string[]>([]);

/** 是否正在批量下线实例。 */
const isBatchUndeploying = ref(false);

/** 限制同时销毁的工作负载数量，避免批量请求压垮 Agent。 */
const BATCH_UNDEPLOY_CONCURRENCY = 4;
const BATCH_UNDEPLOY_NOTIFICATION_DURATION = 10_000;

const mapWithConcurrency = async <T, R>(
  items: T[],
  concurrency: number,
  mapper: (item: T) => Promise<R>,
): Promise<R[]> => {
  const results = new Array<R>(items.length);
  let cursor = 0;
  const workerCount = Math.min(concurrency, items.length);

  const workers = Array.from({ length: workerCount }, async () => {
    while (cursor < items.length) {
      const index = cursor;
      cursor += 1;
      results[index] = await mapper(items[index]);
    }
  });
  await Promise.all(workers);
  return results;
};

const isUndeploying = (instanceId: string) =>
  undeployingInstanceIds.value.includes(instanceId);

const setInstancesUndeploying = (
  instanceIds: string[],
  undeploying: boolean,
) => {
  const next = new Set(undeployingInstanceIds.value);
  for (const instanceId of instanceIds) {
    if (undeploying) next.add(instanceId);
    else next.delete(instanceId);
  }
  undeployingInstanceIds.value = [...next];
};

/** 部署确认按钮可用状态。套件固定部署到本地节点。 */
const canConfirmDeploy = computed(
  () => deployForm.value.nodeId === "local" && !isDeploying.value,
);

/** 部署弹窗默认目标节点。 */
const defaultDeployNodeId = computed(() => "local");

/** 运行中实例列表表格列配置项 */
const instanceColumns = computed<VeyTableColumn[]>(() => [
  {
    label: "",
    slot: "selection",
    headerSlot: "selectionHeader",
    width: 50,
    align: "center",
  },
  { label: t("common.index"), width: 70, align: "center", slot: "index" },
  {
    label: t("app.simulation.rules.fields.name"),
    minWidth: 180,
    align: "center",
    slot: "rule",
  },
  {
    prop: "endpoints",
    label: t("app.simulation.deployments.port"),
    width: 180,
    align: "center",
    slot: "endpoints",
  },
  {
    label: t("app.simulation.deployments.fields.status"),
    width: 120,
    align: "center",
    slot: "status",
  },
  {
    label: t("app.simulation.deployments.fields.forensic"),
    width: 240,
    align: "center",
    slot: "forensic",
  },
  { label: t("common.actions"), width: 100, align: "center", slot: "actions" },
]);

/** 规则管理列表表格列配置项 */
const extendedRuleColumns = computed<VeyTableColumn[]>(() => [
  { label: t("common.index"), width: 70, align: "center", slot: "index" },
  {
    label: t("app.simulation.rules.fields.name"),
    minWidth: 180,
    slot: "name",
    align: "center",
  },
  {
    prop: "cve",
    label: t("app.simulation.rules.fields.cve"),
    width: 140,
    align: "center",
    slot: "cve",
  },
  {
    prop: "category",
    label: t("app.simulation.rules.fields.category"),
    width: 160,
    align: "center",
    slot: "category",
  },
  {
    prop: "protocol",
    label: t("app.simulation.rules.fields.protocol"),
    width: 120,
    align: "center",
    slot: "protocol",
  },
  { label: t("common.actions"), width: 220, align: "center", slot: "actions" },
]);

const currentPackage = ref<SimRulePackage | null>(null);
const packageFileInput = ref<HTMLInputElement | null>(null);
const isUploadingPackage = ref(false);

const loadCurrentPackage = async () => {
  try {
    const res = await simulationApi.getCurrentRulePackage();
    if (res.success && res.data) {
      currentPackage.value = res.data;
    } else {
      currentPackage.value = null;
    }
  } catch {
    currentPackage.value = null;
  }
};

const triggerPackageUpload = () => {
  packageFileInput.value?.click();
};

const loadProtocols = async () => {
  try {
    const res = await simulationApi.listProtocols();
    if (res.success && res.data && res.data.length > 0) {
      protocolCapabilities.value = res.data;
    }
  } catch {
    // 保留前端内置协议能力作为兜底，避免接口异常阻断规则创建。
  }
};

const handleUploadPackage = async (event: Event) => {
  const input = event.target as HTMLInputElement;
  if (!input.files || input.files.length === 0) return;
  const file = input.files[0];

  isUploadingPackage.value = true;
  try {
    const res = await simulationApi.importRulePackage(file);
    if (res.success) {
      const isAlreadyLatest =
        res.messageKey ===
        "app.simulation.rules.messages.packageImportAlreadyLatest";
      const successMsg = isAlreadyLatest
        ? t("app.simulation.rules.messages.packageImportAlreadyLatest")
        : t("app.simulation.rules.messages.packageImportSuccess");

      if (isAlreadyLatest) {
        notificationStore.info(successMsg);
      } else {
        notificationStore.success(successMsg);
      }
      await loadCurrentPackage();
      await loadRules();
    } else {
      notificationStore.error(
        res.message || t("app.simulation.rules.messages.packageImportFailed"),
      );
    }
  } catch (err) {
    const errMsg =
      (err as { response?: { data?: { message?: string } } }).response?.data
        ?.message || t("app.simulation.rules.messages.packageImportError");
    notificationStore.error(errMsg);
  } finally {
    isUploadingPackage.value = false;
    input.value = "";
  }
};

/**
 * 异步拉取并加载数据库中存储的协议仿真规则列表
 */
const loadRules = async (silent = false) => {
  if (!silent) rulesLoading.value = true;
  try {
    const res = await simulationApi.listRules();
    if (res.success && res.data) {
      rules.value = res.data;
    }
  } catch {
    notificationStore.error(t("app.simulation.rules.messages.loadFailed"));
  } finally {
    if (!silent) rulesLoading.value = false;
  }
};

/**
 * 固定本地节点。套件 UI 不再提供节点选择。
 */
const loadNodes = async () => {
  nodes.value = [
    {
      nodeId: "local",
      name: t("app.nodes.local"),
      groupName: "default",
      address: "127.0.0.1",
      status: "online",
      tags: ["local"],
    },
  ];
  selectedNodeId.value = "local";
  deployForm.value.nodeId = "local";
};

/**
 * 获取当前套件上下文中正在运行的仿真实例列表。
 * @param silent 若为 true，则启用静默加载，不展示可能导致屏幕闪烁的全局 Loading 遮罩层。这常用于静默轮询。
 */
const loadNodeInstances = async (silent = false) => {
  if (!selectedNodeId.value) return;
  selectedInstanceIds.value = [];
  if (!silent) deploymentsLoading.value = true;
  try {
    const instRes = await simulationApi.listInstances();
    if (instRes.success && instRes.data) {
      instances.value = instRes.data;
      prunePcapStartClientTimes();
    }
  } catch {
    notificationStore.error(
      t("app.simulation.deployments.messages.loadInstancesFailed"),
    );
  } finally {
    if (!silent) deploymentsLoading.value = false;
  }
};

watch(activeTab, (tab) => {
  if (tab === "rules") {
    void loadCurrentPackage();
    void loadRules();
    scheduleRulesPageSizeUpdate();
  } else if (tab === "deployments") {
    void loadNodes();
    void loadNodeInstances();
  }
});

/** 秒级递增的系统当前时间戳，用于本地实时倒计时/正计时运算 */
const nowSec = ref(Math.floor(Date.now() / 1000));
let timerId: ReturnType<typeof setInterval> | null = null;
let refreshingExpiredCaptures = false;
const pcapStartClientTimes = ref<Record<string, number>>({});

const getPcapStartTime = (row: SimInstance) =>
  pcapStartClientTimes.value[row.instanceId] ?? row.pcapStartTime;

const setPcapStartClientTime = (instanceId: string) => {
  pcapStartClientTimes.value = {
    ...pcapStartClientTimes.value,
    [instanceId]: Math.floor(Date.now() / 1000),
  };
};

const clearPcapStartClientTime = (instanceId: string) => {
  const next = { ...pcapStartClientTimes.value };
  delete next[instanceId];
  pcapStartClientTimes.value = next;
};

const prunePcapStartClientTimes = () => {
  const capturingIds = new Set(
    instances.value
      .filter((instance) => instance.pcapStatus === "capturing")
      .map((instance) => instance.instanceId),
  );
  pcapStartClientTimes.value = Object.fromEntries(
    Object.entries(pcapStartClientTimes.value).filter(([instanceId]) =>
      capturingIds.has(instanceId),
    ),
  );
};

/**
 * 计算并格式化当前实例开启抓包取证的累计运行流逝时间（例如: 01:23 / 05:00）
 * @param row 目标仿真运行实例
 */
const getCaptureTimeStr = (row: SimInstance) => {
  const startedAt = getPcapStartTime(row);
  if (!startedAt) return "00:00 / 05:00";
  const elapsed = Math.max(0, nowSec.value - startedAt);
  const pad = (num: number) => String(num).padStart(2, "0");
  const m = Math.floor(elapsed / 60);
  const s = elapsed % 60;
  return `${pad(m)}:${pad(s)} / 05:00`;
};

/** 正在执行 PCAP 状态切换的实例 ID 集合，用于按行展示 loading 状态。 */
const togglingPcapInstanceIds = ref<string[]>([]);

const isTogglingPcap = (instanceId: string) =>
  togglingPcapInstanceIds.value.includes(instanceId);

const setPcapToggling = (instanceId: string, toggling: boolean) => {
  if (toggling) {
    if (!togglingPcapInstanceIds.value.includes(instanceId)) {
      togglingPcapInstanceIds.value = [
        ...togglingPcapInstanceIds.value,
        instanceId,
      ];
    }
    return;
  }
  togglingPcapInstanceIds.value = togglingPcapInstanceIds.value.filter(
    (id) => id !== instanceId,
  );
};

const applyInstanceUpdate = (updated: SimInstance) => {
  const index = instances.value.findIndex(
    (item) => item.instanceId === updated.instanceId,
  );
  if (index === -1) return;
  instances.value.splice(index, 1, updated);
  prunePcapStartClientTimes();
};

const isCaptureActive = (row: SimInstance) =>
  row.pcapStatus === "capturing" && !!row.pcapStartTime;

const isCaptureStarting = (row: SimInstance) =>
  isTogglingPcap(row.instanceId) ||
  (row.pcapStatus === "capturing" && !row.pcapStartTime);

/**
 * 下发指令开始对目标协议仿真实例进行流量取证（PCAP 包捕获）
 * @param row 目标仿真运行实例
 */
const handleStartCapture = async (row: SimInstance) => {
  if (isTogglingPcap(row.instanceId)) return;
  setPcapToggling(row.instanceId, true);
  try {
    const res = await simulationApi.startCapture(row.instanceId);
    if (res.success && res.data) {
      nowSec.value = Math.floor(Date.now() / 1000);
      setPcapStartClientTime(row.instanceId);
      applyInstanceUpdate(res.data);
      notificationStore.success(
        t("app.simulation.forensic.messages.startSuccess"),
      );
    } else {
      notificationStore.error(
        res.message || t("app.simulation.forensic.messages.startFailed"),
      );
    }
  } catch (err: unknown) {
    const errMsg =
      err instanceof Error
        ? err.message
        : t("app.simulation.forensic.messages.startFailed");
    notificationStore.error(errMsg);
  } finally {
    setPcapToggling(row.instanceId, false);
  }
};

/**
 * 下发指令停止当前实例的抓包取证行为。
 * 包含对空包（文件体积不满足 24 字节链路帧底线）的拦截设计。
 * 如果检测到生成的是空 PCAP（触发后台状态变更为 idle，信标重置），将弹出警告说明流量全空；
 * 否则等待后台同步停止抓包并落盘为可下载文件。
 * @param row 目标仿真运行实例
 */
const handleStopCapture = async (row: SimInstance) => {
  if (isTogglingPcap(row.instanceId)) return;
  setPcapToggling(row.instanceId, true);
  try {
    const res = await simulationApi.stopCapture(row.instanceId);
    if (res.success && res.data) {
      applyInstanceUpdate(res.data);
      clearPcapStartClientTime(row.instanceId);
      if (res.data.pcapStatus === "idle") {
        const message = t("app.simulation.forensic.messages.emptyPcap");
        notificationStore.warning(message);
      } else {
        notificationStore.success(
          t("app.simulation.forensic.messages.stopSuccess"),
        );
      }
    } else {
      notificationStore.error(
        res.message || t("app.simulation.forensic.messages.stopFailed"),
      );
    }
  } catch (err: unknown) {
    const errMsg =
      err instanceof Error
        ? err.message
        : t("app.simulation.forensic.messages.stopFailed");
    notificationStore.error(errMsg);
  } finally {
    setPcapToggling(row.instanceId, false);
  }
};

/**
 * 重置仿真实例的抓包取证状态，物理擦除之前已持久化存盘的 PCAP 数据文件
 * @param row 目标仿真运行实例
 */
const handleResetPcap = async (row: SimInstance) => {
  if (isTogglingPcap(row.instanceId)) return;
  const confirmed = await modalStore.showConfirmation(
    t("app.simulation.forensic.resetTip"),
    t("app.simulation.forensic.resetTitle"),
  );
  if (confirmed) {
    setPcapToggling(row.instanceId, true);
    try {
      const res = await simulationApi.resetCapture(row.instanceId);
      if (res.success && res.data) {
        applyInstanceUpdate(res.data);
        clearPcapStartClientTime(row.instanceId);
        notificationStore.success(
          t("app.simulation.forensic.messages.resetSuccess"),
        );
      } else {
        notificationStore.error(
          res.message || t("app.simulation.forensic.messages.resetFailed"),
        );
      }
    } catch (err: unknown) {
      const errMsg =
        err instanceof Error
          ? err.message
          : t("app.simulation.forensic.messages.resetFailed");
      notificationStore.error(errMsg);
    } finally {
      setPcapToggling(row.instanceId, false);
    }
  }
};

onMounted(() => {
  registerConfirmationHandler(
    (options) =>
      new Promise<boolean>((resolve) => {
        confirmationResolver = resolve;
        confirmationState.value = {
          visible: true,
          message: options.message,
          title: options.title || t("confirmation.confirm"),
          confirmText: options.confirmText || t("confirmation.confirm"),
          cancelText: options.cancelText || t("confirmation.cancel"),
        };
      }),
  );

  // 动态拼装用于与沙箱仿真配合的 Veydeck 系统回调监听端点
  deployForm.value.callbackUrl = simulationApi.getCallbackUrl();

  void loadProtocols();
  void loadNodes();
  void loadCurrentPackage();
  void loadRules();
  void loadNodeInstances();

  // 维持秒级累加计时器，服务于流量捕获倒计时的状态刷新
  timerId = setInterval(() => {
    nowSec.value = Math.floor(Date.now() / 1000);
    const hasExpiredCapture = instances.value.some((instance) => {
      const startedAt = getPcapStartTime(instance);
      return (
        instance.pcapStatus === "capturing" &&
        !!startedAt &&
        nowSec.value - startedAt >= 300
      );
    });
    if (
      activeTab.value === "deployments" &&
      hasExpiredCapture &&
      !refreshingExpiredCaptures
    ) {
      refreshingExpiredCaptures = true;
      void loadNodeInstances(true).finally(() => {
        refreshingExpiredCaptures = false;
      });
    }
  }, 1000);
});

onUnmounted(() => {
  registerConfirmationHandler(null);
  resolveConfirmation(false);
  rulesTableResizeObserver?.disconnect();
  if (rulesPageSizeFrame !== null) {
    cancelAnimationFrame(rulesPageSizeFrame);
  }
  if (timerId) {
    clearInterval(timerId);
  }
});

/** 辅助类型断言，安全强制转换类型便于在插槽中安全提取模型字段 */
const toInstance = (row: unknown) => row as SimInstance;

/** 按主机端口合并传输协议，例如 1053/TCP/UDP。 */
const formatInstanceEndpoints = (instance: SimInstance) => {
  const transportsByPort = new Map<number, string[]>();
  for (const endpoint of instance.endpoints) {
    const transports = transportsByPort.get(endpoint.hostPort) ?? [];
    const transport = endpoint.transport.toUpperCase();
    if (!transports.includes(transport)) transports.push(transport);
    transportsByPort.set(endpoint.hostPort, transports);
  }
  return [...transportsByPort.entries()]
    .map(([port, transports]) => `${port}/${transports.join("/")}`)
    .join(", ");
};

/** 控制新建自定义规则弹窗（Dialog）的打开状态 */
const isRuleDialogOpen = ref(false);
const isCreatingRule = ref(false);
const ruleEditorMode = ref<"guided" | "json">("guided");
const advancedRuleJson = ref("{}");

/** 新建诱捕规则的数据表单模型 */
const ruleForm = ref({
  name: "",
  protocol: "http" as SimulationProtocol,
  defaultPort: SIMULATION_PROTOCOL_DEFAULT_PORTS.http,
  serverHeader: "nginx/1.24.0 (Ubuntu)",
  html: "",
  banner: "",
  hostname: "mail.veydeck.local",
  requireAuth: false,
  password: "",
  serverName: "UNIX Type: L8",
  allowAnonymous: false,
  rdpFlags: "",
});

interface ExploitPathForm {
  path: string;
  triggerMethod: string;
  responseStatus: string;
  responseBody: string;
}

interface KeyValueForm {
  key: string;
  value: string;
}

interface CommandResponseForm {
  command: string;
  argsContains: string;
  response: string;
}

interface CredentialForm {
  username: string;
  password: string;
  displayName: string;
}

interface MailMessageForm {
  from: string;
  to: string;
  subject: string;
  body: string;
}

/** 动态添加/删除的蜜罐特定触发蜜饵路径及其静态伪装响应内容数据模型 */
const exploitPaths = ref<ExploitPathForm[]>([]);
const redisKeys = ref<KeyValueForm[]>([]);
const commandResponses = ref<CommandResponseForm[]>([]);
const credentials = ref<CredentialForm[]>([]);
const mailMessages = ref<MailMessageForm[]>([]);
const dynamicFieldValues = ref<Record<string, string>>({});

const currentProtocolCapability = computed(() =>
  protocolCapabilities.value.find(
    (item) => item.protocol === ruleForm.value.protocol,
  ),
);

const dynamicProtocolFields = computed(() =>
  (currentProtocolCapability.value?.fields ?? []).filter(
    (field) =>
      ["text", "string_list", "number"].includes(field.kind) &&
      !["banner", "server_header", "password"].includes(field.path) &&
      !(
        field.path === "hostname" &&
        ["smtp", "pop3", "imap"].includes(ruleForm.value.protocol)
      ),
  ),
);

const isHttpRuleForm = computed(() => ruleForm.value.protocol === "http");
const isRedisRuleForm = computed(() => ruleForm.value.protocol === "redis");
const keyValueFieldPath = computed(() => {
  if (ruleForm.value.protocol === "redis") return "keys";
  if (ruleForm.value.protocol === "dns") return "records";
  if (ruleForm.value.protocol === "memcached") return "stats";
  if (ruleForm.value.protocol === "snmp") return "oids";
  return "";
});
const isKeyValueRuleForm = computed(() => Boolean(keyValueFieldPath.value));
const keyValueLocaleSection = computed(() => {
  if (ruleForm.value.protocol === "dns") return "dnsRecords";
  if (ruleForm.value.protocol === "memcached") return "memcachedStats";
  if (ruleForm.value.protocol === "snmp") return "snmpOids";
  return "redisKeys";
});
const keyValueText = (key: string) =>
  t(`app.simulation.rules.${keyValueLocaleSection.value}.${key}`);
const isMailRuleForm = computed(() =>
  ["smtp", "pop3", "imap"].includes(ruleForm.value.protocol),
);
const isCredentialRuleForm = computed(() =>
  (currentProtocolCapability.value?.fields.length ?? 0) > 0
    ? currentProtocolCapability.value?.fields.some(
        (field) => field.kind === "credentials",
      )
    : [
        "smtp",
        "pop3",
        "imap",
        "ssh",
        "ftp",
        "rdp",
        "telnet",
        "mysql",
        "postgresql",
        "ldap",
      ].includes(ruleForm.value.protocol),
);
const showBannerField = computed(() =>
  (currentProtocolCapability.value?.fields.length ?? 0) > 0
    ? currentProtocolCapability.value?.fields.some(
        (field) => field.path === "banner",
      )
    : ["redis", "smtp", "pop3", "imap", "ssh", "ftp", "telnet"].includes(
        ruleForm.value.protocol,
      ),
);

const currentProtocolDefaultPort = computed(() =>
  getProtocolDefaultPort(ruleForm.value.protocol),
);

const getProtocolDefaultPort = (protocol: SimulationProtocol) =>
  protocolCapabilities.value.find((item) => item.protocol === protocol)
    ?.defaultPort ?? SIMULATION_PROTOCOL_DEFAULT_PORTS[protocol];

const ruleNamePlaceholder = computed(() => {
  const key = `app.simulation.rules.namePlaceholders.${ruleForm.value.protocol}`;
  const label = t(key);
  return label === key
    ? t("app.simulation.rules.fields.namePlaceholder")
    : label;
});

const resetProtocolSpecificForm = (protocol: SimulationProtocol) => {
  ruleForm.value.defaultPort = getProtocolDefaultPort(protocol);
  ruleForm.value.serverHeader = "nginx/1.24.0 (Ubuntu)";
  ruleForm.value.html = "";
  ruleForm.value.banner = defaultProtocolBanner(protocol);
  ruleForm.value.hostname = "mail.veydeck.local";
  ruleForm.value.requireAuth = ["redis", "smtp", "pop3", "imap"].includes(
    protocol,
  );
  ruleForm.value.password = protocol === "redis" ? "redis123" : "";
  ruleForm.value.serverName = "UNIX Type: L8";
  ruleForm.value.allowAnonymous = false;
  ruleForm.value.rdpFlags = protocol === "rdp" ? "1" : "";
  dynamicFieldValues.value = {
    server_version:
      protocol === "mysql"
        ? "8.0.36-veydeck"
        : protocol === "postgresql"
          ? "16.2-veydeck"
          : protocol === "mongodb"
            ? "7.0.14-veydeck"
            : protocol === "memcached"
              ? "1.6.24"
              : "",
    hostname: protocol === "mongodb" ? "mongodb-veydeck" : "",
    max_wire_version: protocol === "mongodb" ? "21" : "",
    databases: "",
    server_name: protocol === "smb" ? "Veydeck" : "",
    domain: protocol === "smb" ? "LAB" : "",
    shares: "",
    base_dn: protocol === "ldap" ? "dc=lab,dc=example" : "",
    prompt: protocol === "telnet" ? "$ " : "",
    default_ipv4: protocol === "dns" ? "192.0.2.53" : "",
    ttl: protocol === "dns" ? "60" : "",
    community: protocol === "snmp" ? "public" : "",
    system_description: protocol === "snmp" ? "Linux veydeck-snmp 6.8.0" : "",
    system_name: protocol === "snmp" ? "snmp-veydeck" : "",
    system_location: protocol === "snmp" ? "Veydeck" : "",
    protocol_version: protocol === "vnc" ? "3.8" : "",
    security_types: protocol === "vnc" ? "none" : "",
  };
  exploitPaths.value = [];
  redisKeys.value =
    protocol === "dns"
      ? [{ key: "dns.veydeck.local", value: "192.0.2.53" }]
      : [];
  ruleForm.value.allowAnonymous = protocol === "mqtt";
  commandResponses.value = [];
  credentials.value = isCredentialRuleForm.value
    ? [
        {
          username: defaultCredentialUsername(protocol),
          password: "password",
          displayName: "",
        },
      ]
    : [];
  mailMessages.value = isMailRuleForm.value
    ? [
        {
          from: "alerts@veydeck.local",
          to: "admin@veydeck.local",
          subject: "Security Alert",
          body: "Suspicious login detected.",
        },
      ]
    : [];
};

const defaultProtocolBanner = (protocol: SimulationProtocol) => {
  if (protocol === "smtp") return "220 mail.veydeck.local ESMTP";
  if (protocol === "pop3") return "+OK POP3 server ready";
  if (protocol === "imap") return "* OK IMAP4rev1 Service Ready";
  if (protocol === "ssh") return "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1";
  if (protocol === "ftp") return "ProFTPD 1.3.5e Server ready.";
  if (protocol === "redis") return "Redis server ready";
  if (protocol === "telnet") return "Embedded Linux 4.19";
  return "";
};

const defaultCredentialUsername = (protocol: SimulationProtocol) => {
  if (protocol === "ssh") return "root";
  if (protocol === "rdp") return "administrator";
  if (protocol === "mysql") return "app";
  if (protocol === "postgresql") return "postgres";
  if (protocol === "ldap") return "cn=reader,dc=lab,dc=example";
  return "admin";
};

/**
 * 重置表单状态，调起创建自定义仿真协议规则弹窗
 */
const openNewRuleDialog = () => {
  ruleForm.value = {
    name: "",
    protocol: "http",
    defaultPort: SIMULATION_PROTOCOL_DEFAULT_PORTS.http,
    serverHeader: "nginx/1.24.0 (Ubuntu)",
    html: "",
    banner: "",
    hostname: "mail.veydeck.local",
    requireAuth: false,
    password: "",
    serverName: "UNIX Type: L8",
    allowAnonymous: false,
    rdpFlags: "",
  };
  resetProtocolSpecificForm("http");
  ruleEditorMode.value = "guided";
  advancedRuleJson.value = "{}";
  isRuleDialogOpen.value = true;
};

const setRuleEditorMode = (mode: "guided" | "json") => {
  if (mode === "json" && ruleEditorMode.value !== "json") {
    advancedRuleJson.value = JSON.stringify(buildRuleConfig(), null, 2);
  }
  ruleEditorMode.value = mode;
};

watch(
  () => ruleForm.value.protocol,
  (protocol) => {
    resetProtocolSpecificForm(protocol);
  },
);

/**
 * 为当前自定义规则的配置项动态新增一条漏洞模拟响应路径
 */
const addExploitPath = () => {
  exploitPaths.value.push({
    path: "",
    triggerMethod: "ANY",
    responseStatus: "200",
    responseBody: "",
  });
};

/**
 * 根据索引移除配置项中指定的漏洞模拟响应路径
 * @param index 计划移除的数组索引下标
 */
const removeExploitPath = (index: number) => {
  exploitPaths.value.splice(index, 1);
};

const addRedisKey = () => {
  redisKeys.value.push({ key: "", value: "" });
};

const removeRedisKey = (index: number) => {
  redisKeys.value.splice(index, 1);
};

const addCommandResponse = () => {
  commandResponses.value.push({ command: "", argsContains: "", response: "" });
};

const removeCommandResponse = (index: number) => {
  commandResponses.value.splice(index, 1);
};

const addCredential = () => {
  credentials.value.push({
    username: defaultCredentialUsername(ruleForm.value.protocol),
    password: "",
    displayName: "",
  });
};

const removeCredential = (index: number) => {
  credentials.value.splice(index, 1);
};

const addMailMessage = () => {
  mailMessages.value.push({
    from: "alerts@veydeck.local",
    to: "admin@veydeck.local",
    subject: "",
    body: "",
  });
};

const removeMailMessage = (index: number) => {
  mailMessages.value.splice(index, 1);
};

const buildCredentialsConfig = () =>
  credentials.value
    .filter((item) => item.username || item.password)
    .map((item) => ({
      username: item.username,
      password: item.password,
      display_name: item.displayName || undefined,
    }));

const buildCommandResponsesConfig = () =>
  commandResponses.value
    .filter((item) => item.command && item.response)
    .map((item) => ({
      command: item.command,
      args_contains: item.argsContains
        ? item.argsContains
            .split(",")
            .map((value) => value.trim())
            .filter(Boolean)
        : undefined,
      response: item.response,
      event_type: "exploit_attempt",
    }));

const buildMailMessagesConfig = () =>
  mailMessages.value
    .filter((item) => item.subject || item.body)
    .map((item, index) => ({
      uid: String(index + 1),
      from: item.from || "alerts@veydeck.local",
      to: item.to
        .split(",")
        .map((value) => value.trim())
        .filter(Boolean),
      subject: item.subject,
      body: item.body,
      flags: [],
    }));

const buildRuleConfig = () => {
  const protocol = ruleForm.value.protocol;
  if (protocol === "http") {
    return {
      server_header: ruleForm.value.serverHeader || undefined,
      html: ruleForm.value.html || undefined,
      exploit_paths: exploitPaths.value.map((ep) => ({
        path: ep.path,
        trigger_method: ep.triggerMethod === "ANY" ? null : ep.triggerMethod,
        response_status: parseInt(ep.responseStatus, 10) || 200,
        response_body: ep.responseBody,
      })),
    };
  }

  if (protocol === "redis") {
    const keys = Object.fromEntries(
      redisKeys.value
        .filter((item) => item.key)
        .map((item) => [item.key, item.value]),
    );
    return {
      banner: ruleForm.value.banner || undefined,
      require_auth: ruleForm.value.requireAuth,
      password: ruleForm.value.password || undefined,
      keys,
      command_responses: buildCommandResponsesConfig(),
    };
  }

  if (protocol === "smtp") {
    return {
      banner: ruleForm.value.banner || undefined,
      hostname: ruleForm.value.hostname || undefined,
      require_auth: ruleForm.value.requireAuth,
      credentials: buildCredentialsConfig(),
      custom_responses: buildCommandResponsesConfig(),
    };
  }

  if (protocol === "pop3") {
    return {
      banner: ruleForm.value.banner || undefined,
      require_auth: ruleForm.value.requireAuth,
      credentials: buildCredentialsConfig(),
      messages: buildMailMessagesConfig(),
      custom_responses: buildCommandResponsesConfig(),
    };
  }

  if (protocol === "imap") {
    const messages = buildMailMessagesConfig();
    return {
      banner: ruleForm.value.banner || undefined,
      require_auth: ruleForm.value.requireAuth,
      credentials: buildCredentialsConfig(),
      mailboxes: {
        INBOX: messages,
      },
      messages,
      custom_responses: buildCommandResponsesConfig(),
    };
  }

  if (protocol === "ssh") {
    return {
      banner: ruleForm.value.banner || undefined,
      credentials: buildCredentialsConfig(),
    };
  }

  if (protocol === "ftp") {
    return {
      banner: ruleForm.value.banner || undefined,
      credentials: buildCredentialsConfig(),
      server_name: ruleForm.value.serverName || undefined,
      allow_anonymous: ruleForm.value.allowAnonymous,
    };
  }

  if (protocol === "telnet") {
    return {
      banner: ruleForm.value.banner || undefined,
      prompt: dynamicFieldValues.value.prompt || "$ ",
      credentials: buildCredentialsConfig(),
      command_responses: {},
    };
  }

  if (protocol === "mysql" || protocol === "postgresql") {
    return {
      server_version: dynamicFieldValues.value.server_version || undefined,
      credentials: buildCredentialsConfig(),
      databases: splitDynamicList("databases"),
      query_responses: {},
    };
  }

  if (protocol === "smb") {
    return {
      server_name: dynamicFieldValues.value.server_name || "Veydeck",
      domain: dynamicFieldValues.value.domain || "LAB",
      shares: splitDynamicList("shares"),
    };
  }

  if (protocol === "ldap") {
    return {
      base_dn: dynamicFieldValues.value.base_dn || "dc=lab,dc=example",
      credentials: buildCredentialsConfig(),
      entries: [],
    };
  }

  if (protocol === "dns") {
    return {
      records: Object.fromEntries(
        redisKeys.value
          .filter((item) => item.key)
          .map((item) => [item.key, item.value]),
      ),
      default_ipv4: dynamicFieldValues.value.default_ipv4 || undefined,
      ttl: parseInt(dynamicFieldValues.value.ttl || "60", 10) || 60,
    };
  }

  if (protocol === "mongodb") {
    return {
      server_version: dynamicFieldValues.value.server_version || undefined,
      hostname: dynamicFieldValues.value.hostname || undefined,
      max_wire_version:
        parseInt(dynamicFieldValues.value.max_wire_version || "21", 10) || 21,
    };
  }

  if (protocol === "memcached") {
    return {
      server_version: dynamicFieldValues.value.server_version || undefined,
      stats: Object.fromEntries(
        redisKeys.value
          .filter((item) => item.key)
          .map((item) => [item.key, item.value]),
      ),
    };
  }

  if (protocol === "snmp") {
    return {
      community: dynamicFieldValues.value.community || "public",
      system_description:
        dynamicFieldValues.value.system_description || undefined,
      system_name: dynamicFieldValues.value.system_name || undefined,
      system_location: dynamicFieldValues.value.system_location || undefined,
      oids: Object.fromEntries(
        redisKeys.value
          .filter((item) => item.key)
          .map((item) => [item.key, item.value]),
      ),
    };
  }

  if (protocol === "mqtt") {
    return { allow_anonymous: ruleForm.value.allowAnonymous };
  }

  if (protocol === "vnc") {
    return {
      protocol_version: dynamicFieldValues.value.protocol_version || "3.8",
      security_types: splitDynamicList("security_types"),
    };
  }

  return {
    flags: parseInt(ruleForm.value.rdpFlags, 10) || undefined,
    credentials: buildCredentialsConfig(),
  };
};

const splitDynamicList = (path: string) =>
  (dynamicFieldValues.value[path] || "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);

/**
 * 向控制端提交创建新的诱捕仿真规则请求。
 * 转换前台模型数据至符合后端接口定义的 YAML/JSON 序列化配置结构。
 */
const handleCreateRule = async () => {
  if (isCreatingRule.value) return;

  if (!ruleForm.value.name) {
    notificationStore.error(t("app.simulation.rules.messages.nameRequired"));
    return;
  }

  isCreatingRule.value = true;
  isLoading.value = true;
  try {
    let config: unknown;
    try {
      config =
        ruleEditorMode.value === "json"
          ? JSON.parse(advancedRuleJson.value)
          : buildRuleConfig();
    } catch {
      notificationStore.error(t("app.simulation.rules.messages.invalidJson"));
      return;
    }
    const res = await simulationApi.createRule({
      name: ruleForm.value.name,
      protocol: ruleForm.value.protocol,
      defaultPort:
        ruleForm.value.defaultPort || currentProtocolDefaultPort.value,
      configYaml: JSON.stringify(config),
    });

    if (res.success && res.data) {
      notificationStore.success(
        t("app.simulation.rules.messages.createSuccess"),
      );
      isRuleDialogOpen.value = false;
      await loadRules();
    } else {
      notificationStore.error(
        res.message || t("app.simulation.rules.messages.createFailed"),
      );
    }
  } catch {
    notificationStore.error(t("app.simulation.rules.messages.createError"));
  } finally {
    isCreatingRule.value = false;
    isLoading.value = false;
  }
};

/**
 * 物理删除特定的自定义仿真规则，内置保护防止删除系统预置规则（ID <= 999999 属于内置）。
 * @param id 规则物理 ID
 * @param name 规则文本描述名称
 */
const handleDeleteRule = async (id: number, name: string) => {
  if (id <= BUILTIN_RULE_MAX_ID) {
    notificationStore.error(
      t("app.simulation.rules.messages.builtinDeleteNotAllowed"),
    );
    return;
  }

  const confirmed = await modalStore.showConfirmation(
    t("app.simulation.rules.deleteConfirm", { name }),
    t("app.simulation.rules.deleteBtn"),
    t("app.simulation.rules.deleteBtn"),
    t("confirmation.cancel"),
  );
  if (!confirmed) return;

  isLoading.value = true;
  try {
    const res = await simulationApi.deleteRule(id);
    if (res.success) {
      notificationStore.success(
        t("app.simulation.rules.messages.deleteSuccess"),
      );
      await loadRules();
    } else {
      notificationStore.error(
        res.message || t("app.simulation.rules.messages.deleteFailed"),
      );
    }
  } catch {
    notificationStore.error(t("app.simulation.rules.messages.deleteError"));
  } finally {
    isLoading.value = false;
  }
};

/**
 * 打开规则详细信息查看抽屉
 * @param row 选中的规则数据模型
 */
const openDetailDrawer = (row: SimRule) => {
  ruleDetail.value = row;
  isDetailDrawerOpen.value = true;
};

/**
 * 快速查看已部署实例所绑定的规则详情
 * @param row 运行实例对象
 */
const handleShowInstanceRuleDetail = async (row: SimInstance) => {
  let rule = rules.value.find((r) => r.id === row.ruleId);
  if (!rule) {
    await loadRules();
    rule = rules.value.find((r) => r.id === row.ruleId);
  }
  if (rule) {
    openDetailDrawer(rule);
  } else {
    notificationStore.error(t("app.simulation.rules.messages.loadFailed"));
  }
};

/**
 * 开启部署仿真模块的表单对话框，初始化部署端口与所属规则参数
 * @param row 待部署的诱捕仿真规则模型
 */
const openDeployDialog = (row: SimRule) => {
  ruleToDeploy.value = row;
  deployForm.value.ruleId = row.id;
  const capability = protocolCapabilities.value.find(
    (item) => item.protocol === row.protocol,
  );
  deployForm.value.port =
    row.defaultPort || capability?.endpoints[0]?.defaultHostPort || 8080;
  deployForm.value.endpointIds = capability?.endpoints.length
    ? capability.endpoints.map((endpoint) => endpoint.id)
    : row.protocol === "dns"
      ? ["dns-tcp", "dns-udp"]
      : ["main"];
  deployForm.value.nodeId = defaultDeployNodeId.value;
  isDeployDialogOpen.value = true;
};

/** 在部署请求完成前保持弹窗打开。 */
const closeDeployDialog = () => {
  if (!isDeploying.value) {
    isDeployDialogOpen.value = false;
  }
};

/**
 * 执行向边缘或本地在线节点部署并动态开启仿真服务监听指令。
 * 内置对监听端口段（1-65535）的安全校验。
 */
const executeDeploy = async () => {
  if (isDeploying.value) return;

  if (!canConfirmDeploy.value) {
    notificationStore.error(
      t("app.simulation.deployments.messages.nodeRequired"),
    );
    return;
  }
  if (!deployForm.value.ruleId) {
    notificationStore.error(
      t("app.simulation.deployments.messages.ruleRequired"),
    );
    return;
  }
  const port = parseInt(String(deployForm.value.port), 10);
  if (isNaN(port) || port <= 0 || port > 65535) {
    notificationStore.error(
      t("app.simulation.deployments.messages.portInvalid"),
    );
    return;
  }

  const deployRule = rules.value.find((p) => p.id === deployForm.value.ruleId);
  const ruleName = deployRule
    ? getRuleName(deployRule)
    : deployForm.value.ruleId;
  const endpointBindings = deployForm.value.endpointIds.map((endpointId) => ({
    endpointId,
    hostPort: port,
  }));

  isDeploying.value = true;
  try {
    const res = await simulationApi.deploySimulation({
      nodeId: deployForm.value.nodeId,
      endpointBindings,
      ruleId: deployForm.value.ruleId,
      veydeckCallbackUrl: deployForm.value.callbackUrl,
    });

    if (res.success && res.data?.status === "error") {
      notificationStore.error(
        res.data.errorMessage ||
          t("app.simulation.deployments.messages.deployFailed", {
            name: ruleName,
          }),
      );
      isDeployDialogOpen.value = false;
    } else if (res.success) {
      notificationStore.success(
        t("app.simulation.deployments.messages.deploySuccess", {
          name: ruleName,
        }),
      );
      isDeployDialogOpen.value = false;
    } else {
      const message =
        res.messageKey === "app.simulation.deployments.messages.portOccupied"
          ? t("app.simulation.deployments.messages.portOccupied")
          : res.message;
      notificationStore.error(
        message ||
          t("app.simulation.deployments.messages.deployFailed", {
            name: ruleName,
          }),
      );
    }
  } catch {
    notificationStore.error(
      t("app.simulation.deployments.messages.deployError", { name: ruleName }),
    );
  } finally {
    isDeploying.value = false;
  }
};

/**
 * 下架/注销目标端口上的指定协议仿真运行实例，物理关闭监听 Socket
 * @param id 仿真运行实例 ID
 */
const handleUndeploy = async (id: string) => {
  if (isUndeploying(id) || isBatchUndeploying.value) return;

  const instance = instances.value.find((inst) => inst.instanceId === id);
  const rule = instance
    ? rules.value.find((p) => p.id === instance.ruleId)
    : null;
  const ruleName = rule ? getRuleName(rule) : instance ? instance.ruleId : id;

  const confirmed = await modalStore.showConfirmation(
    t("app.simulation.deployments.undeployConfirm", { name: ruleName }),
    t("app.simulation.deployments.btnUndeploy"),
    t("app.simulation.deployments.btnUndeploy"),
    t("confirmation.cancel"),
  );
  if (!confirmed) return;
  if (isUndeploying(id) || isBatchUndeploying.value) return;

  setInstancesUndeploying([id], true);
  try {
    const res = await simulationApi.undeploySimulation(id);
    if (res.success) {
      notificationStore.success(
        t("app.simulation.deployments.messages.undeploySuccess", {
          name: ruleName,
        }),
      );
      instances.value = instances.value.filter(
        (inst) => inst.instanceId !== id,
      );
      selectedInstanceIds.value = selectedInstanceIds.value.filter(
        (instanceId) => instanceId !== id,
      );
    } else {
      notificationStore.error(
        res.message ||
          t("app.simulation.deployments.messages.undeployFailed", {
            name: ruleName,
          }),
      );
    }
  } catch {
    notificationStore.error(
      t("app.simulation.deployments.messages.undeployError", {
        name: ruleName,
      }),
    );
  } finally {
    setInstancesUndeploying([id], false);
  }
};

/** 打开与指定运行实例强关联的诱捕审计。 */
const openInstanceAudit = (instance: SimInstance) => {
  const rule = rules.value.find((item) => item.id === instance.ruleId);
  auditInstance.value = {
    ...instance,
    ruleName: getRuleName(rule) || instance.ruleName,
  };
};

/** 构建实例行的统一操作菜单。 */
interface InstanceMenuAction {
  label: string;
  icon: string;
  className?: string;
  disabled?: boolean;
  handler: () => void;
}

const instanceActions = (instance: SimInstance): InstanceMenuAction[] => [
  {
    label: t("app.simulation.deployments.btnAudit"),
    icon: "info",
    handler: () => openInstanceAudit(instance),
  },
  {
    label: t("app.simulation.deployments.btnUndeploy"),
    icon: "trash",
    className: "app-btn-delete",
    disabled: isUndeploying(instance.instanceId) || isBatchUndeploying.value,
    handler: () => void handleUndeploy(instance.instanceId),
  },
];

const isAllSelected = computed(() => {
  if (instances.value.length === 0) return false;
  return instances.value.every((inst) =>
    selectedInstanceIds.value.includes(inst.instanceId),
  );
});

const handleSelectAll = (checked: boolean) => {
  if (checked) {
    selectedInstanceIds.value = instances.value.map((inst) => inst.instanceId);
  } else {
    selectedInstanceIds.value = [];
  }
};

const handleSelectChange = (instanceId: string, checked: boolean) => {
  if (checked) {
    if (!selectedInstanceIds.value.includes(instanceId)) {
      selectedInstanceIds.value.push(instanceId);
    }
  } else {
    selectedInstanceIds.value = selectedInstanceIds.value.filter(
      (id) => id !== instanceId,
    );
  }
};

const getRuleNameForInstance = (instanceId: string) => {
  const inst = instances.value.find((i) => i.instanceId === instanceId);
  const rule = inst ? rules.value.find((r) => r.id === inst.ruleId) : null;
  return rule ? getRuleName(rule) : inst ? String(inst.ruleId) : instanceId;
};

const formatNamesList = (names: string[]) => {
  if (names.length === 0) return "";
  const quoteChar = locale.value === "en" ? '"' : "“";
  const endQuoteChar = locale.value === "en" ? '"' : "”";
  const comma = locale.value === "en" ? ", " : "、";

  if (names.length <= 3) {
    return names.map((n) => `${quoteChar}${n}${endQuoteChar}`).join(comma);
  } else {
    const subset = names.slice(0, 3);
    const extraCount = names.length - 3;
    return t("app.simulation.deployments.messages.truncatedInstanceNames", {
      names: subset
        .map((name) => `${quoteChar}${name}${endQuoteChar}`)
        .join(comma),
      count: extraCount,
    });
  }
};

const handleBatchUndeploy = async () => {
  if (
    selectedInstanceIds.value.length === 0 ||
    isBatchUndeploying.value ||
    undeployingInstanceIds.value.length > 0
  ) {
    return;
  }

  const confirmed = await modalStore.showConfirmation(
    t("app.simulation.deployments.batchUndeployConfirm", {
      count: selectedInstanceIds.value.length,
    }),
    t("app.simulation.deployments.btnBatchUndeploy"),
    t("app.simulation.deployments.btnBatchUndeploy"),
    t("confirmation.cancel"),
  );
  if (!confirmed) return;
  if (isBatchUndeploying.value || undeployingInstanceIds.value.length > 0) {
    return;
  }

  const targetIds = [...selectedInstanceIds.value];
  isBatchUndeploying.value = true;
  setInstancesUndeploying(targetIds, true);
  const successNames: string[] = [];
  const failNames: string[] = [];
  const failIds: string[] = [];

  try {
    const results = await mapWithConcurrency(
      targetIds,
      BATCH_UNDEPLOY_CONCURRENCY,
      async (id) => {
        const ruleName = getRuleNameForInstance(id);
        try {
          const res = await simulationApi.undeploySimulation(id);
          if (res.success) {
            instances.value = instances.value.filter(
              (instance) => instance.instanceId !== id,
            );
            selectedInstanceIds.value = selectedInstanceIds.value.filter(
              (instanceId) => instanceId !== id,
            );
          }
          return { id, ruleName, success: res.success };
        } catch {
          return { id, ruleName, success: false };
        } finally {
          setInstancesUndeploying([id], false);
        }
      },
    );

    for (const result of results) {
      if (result.success) {
        successNames.push(result.ruleName);
      } else {
        failNames.push(result.ruleName);
        failIds.push(result.id);
      }
    }

    if (failNames.length === 0) {
      notificationStore.success(
        t("app.simulation.deployments.messages.batchUndeploySuccess", {
          count: successNames.length,
          names: formatNamesList(successNames),
        }),
        BATCH_UNDEPLOY_NOTIFICATION_DURATION,
      );
    } else if (successNames.length > 0) {
      notificationStore.warning(
        t("app.simulation.deployments.messages.batchUndeployPartial", {
          successCount: successNames.length,
          failCount: failNames.length,
          successNames: formatNamesList(successNames),
          failNames: formatNamesList(failNames),
        }),
        BATCH_UNDEPLOY_NOTIFICATION_DURATION,
      );
    } else {
      notificationStore.error(
        t("app.simulation.deployments.messages.batchUndeployFailed", {
          count: failNames.length,
          names: formatNamesList(failNames),
        }),
        BATCH_UNDEPLOY_NOTIFICATION_DURATION,
      );
    }

    selectedInstanceIds.value = failIds;
  } catch {
    notificationStore.error(
      t("app.simulation.deployments.messages.batchUndeployError"),
      BATCH_UNDEPLOY_NOTIFICATION_DURATION,
    );
  } finally {
    setInstancesUndeploying(targetIds, false);
    isBatchUndeploying.value = false;
  }
};

/**
 * 对仿真规则的漏洞分类标签执行本地多语言翻译
 * @param category 分类代码
 */
const getCategoryLabel = (category: string) => {
  const key = `app.simulation.rules.categories.${category}`;
  const label = t(key);
  return label !== key ? label : category;
};

/**
 * 根据规则类型选择标签颜色，和后端 category 枚举保持一致。
 * @param category 规则分类代码
 */
const getCategoryTagType = (category: string) => {
  if (category === "cve_sim") return "danger";
  if (category === "vuln_sim") return "warning";
  if (category === "honeypot") return "success";
  if (category === "test_env") return "info";
  return "default";
};

/** 当前支持的仿真网络协议族源下拉框选项 */
const protocolOptions = computed(() =>
  customRuleProtocolCapabilities.value.map((item) => ({
    value: item.protocol,
    label: item.label,
  })),
);

/** 自定义仿真规则触发路径中的支持匹配方法 */
const methodOptions = computed(() => [
  { value: "ANY", label: t("app.simulation.rules.exploitPaths.anyMethod") },
  { value: "GET", label: "GET" },
  { value: "POST", label: "POST" },
  { value: "PUT", label: "PUT" },
  { value: "PATCH", label: "PATCH" },
  { value: "DELETE", label: "DELETE" },
  { value: "HEAD", label: "HEAD" },
  { value: "OPTIONS", label: "OPTIONS" },
]);

/**
 * 根据实例监听端口和规则 ID 生成可读的 PCAP 下载文件名。
 * 例如：`veydeck-8080-190001.pcap`。
 * @param row 目标仿真运行实例
 */
const getFriendlyPcapFilename = (row: SimInstance) =>
  `veydeck-${row.listenPort}-${row.ruleId}.pcap`;

/**
 * 按仿真实例下载关联取证 PCAP 包，由后端记录可信操作日志。
 * 下载成功后动态建立临时文件锚点链接，由浏览器拉起标准下载。
 * @param row 目标仿真运行实例
 */
const handleDownloadPcap = async (row: SimInstance) => {
  if (!row.pcapFilePath) return;
  isLoading.value = true;
  try {
    const blob = await simulationApi.downloadPcap(row.instanceId);
    const friendlyFilename = getFriendlyPcapFilename(row);

    const blobUrl = window.URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = blobUrl;
    link.download = friendlyFilename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(blobUrl);
    notificationStore.success(
      t("app.simulation.logs.messages.downloadSuccess"),
    );
  } catch {
    notificationStore.error(t("app.simulation.logs.messages.downloadFailed"));
  } finally {
    isLoading.value = false;
  }
};
</script>

<template>
  <div
    class="simulation-dashboard"
    data-veydeck-app="simulation"
    data-page="simulation-dashboard"
  >
    <!-- 头部横幅与 Tab 选项卡 -->
    <div class="dashboard-header" data-slot="header">
      <VeyTabs
        v-model="activeTabModel"
        :tabs="simulationTabs"
        data-ui="simulation-tabs"
      />
    </div>

    <!-- 主交互面板 -->
    <div class="dashboard-body" data-slot="container">
      <!-- TAB 1: 运行实例 (Deployments) -->
      <div
        v-if="activeTab === 'deployments'"
        class="tab-content flex-column gap-layout"
      >
        <VeySelectionBar
          v-if="selectedInstanceIds.length > 0"
          :count="selectedInstanceIds.length"
          :label="t('app.simulation.deployments.btnBatchUndeploy')"
          :aria-label="t('app.simulation.deployments.btnBatchUndeploy')"
        >
          <VeyButton
            type="danger"
            data-ui="sim-batch-undeploy-btn"
            :loading="isBatchUndeploying"
            :disabled="isBatchUndeploying || undeployingInstanceIds.length > 0"
            @click="handleBatchUndeploy"
          >
            {{ t("app.simulation.deployments.btnBatchUndeploy") }}
          </VeyButton>
        </VeySelectionBar>

        <div class="main-panel flex-column flex-1" data-slot="content">
          <div class="table-body-region flex-1 overflow-auto">
            <VeyTable
              :data="instances"
              :columns="instanceColumns"
              border
              data-ui="sim-deployments-table"
            >
              <template #selectionHeader>
                <VeyCheckbox
                  :model-value="isAllSelected"
                  @change="handleSelectAll"
                />
              </template>
              <template #selection="{ row }">
                <VeyCheckbox
                  :model-value="selectedInstanceIds.includes(row.instanceId)"
                  :disabled="isUndeploying(row.instanceId)"
                  @change="(val) => handleSelectChange(row.instanceId, val)"
                />
              </template>
              <template #index="{ index }">
                {{ index + 1 }}
              </template>
              <template #rule="{ row }">
                <div class="rule-name-cell" data-ui="rule-name-cell">
                  <span
                    v-if="toInstance(row).pcapStatus === 'capturing'"
                    class="capturing-row-indicator"
                    :title="t('app.simulation.forensic.liveRecording')"
                  ></span>
                  <span
                    class="rule-link-text mono"
                    @click="handleShowInstanceRuleDetail(row)"
                  >
                    {{
                      getRuleName(rules.find((p) => p.id === row.ruleId)) ||
                      row.ruleId
                    }}
                  </span>
                </div>
              </template>
              <template #status="{ row }">
                <div class="status-cell">
                  <VeyTag
                    :type="row.status === 'active' ? 'success' : 'danger'"
                    size="small"
                  >
                    {{ row.status.toUpperCase() }}
                  </VeyTag>
                  <VeyTooltip
                    v-if="row.errorMessage"
                    :text="row.errorMessage"
                    position="top"
                  >
                    <span class="status-error-message">{{
                      row.errorMessage
                    }}</span>
                  </VeyTooltip>
                </div>
              </template>
              <template #endpoints="{ row }">
                <span class="mono endpoint-summary">
                  {{ formatInstanceEndpoints(toInstance(row)) }}
                </span>
              </template>
              <template #forensic="{ row }">
                <div class="forensic-cell">
                  <template v-if="isCaptureActive(toInstance(row))">
                    <div class="capturing-wrapper">
                      <div
                        class="live-pulse-bars"
                        :title="t('app.simulation.forensic.intercepting')"
                      >
                        <span class="pulse-bar"></span>
                        <span class="pulse-bar"></span>
                        <span class="pulse-bar"></span>
                        <span class="pulse-bar"></span>
                      </div>
                      <VeyButton
                        type="danger"
                        size="small"
                        data-ui="stop-forensic"
                        :loading="isTogglingPcap(toInstance(row).instanceId)"
                        :disabled="isTogglingPcap(toInstance(row).instanceId)"
                        @click="handleStopCapture(toInstance(row))"
                      >
                        {{ t("app.simulation.forensic.stopBtn") }} ({{
                          getCaptureTimeStr(toInstance(row))
                        }})
                      </VeyButton>
                    </div>
                  </template>
                  <template v-else-if="isCaptureStarting(toInstance(row))">
                    <VeyButton
                      type="primary"
                      size="small"
                      data-ui="start-forensic-loading"
                      loading
                      disabled
                    >
                      {{ t("app.simulation.forensic.startBtn") }}
                    </VeyButton>
                  </template>
                  <template v-else-if="toInstance(row).pcapStatus === 'ready'">
                    <div class="ready-wrapper">
                      <a
                        href="#"
                        class="download-btn-link"
                        data-ui="download-pcap"
                        @click.prevent="handleDownloadPcap(toInstance(row))"
                      >
                        <VeyButton
                          type="primary"
                          size="small"
                          class="download-pulse-btn"
                        >
                          {{ t("app.simulation.forensic.downloadBtn") }}
                        </VeyButton>
                      </a>
                      <VeyButton
                        type="danger"
                        size="small"
                        data-ui="reset-forensic"
                        :loading="isTogglingPcap(toInstance(row).instanceId)"
                        :disabled="isTogglingPcap(toInstance(row).instanceId)"
                        @click="handleResetPcap(toInstance(row))"
                        :title="t('app.simulation.forensic.resetTitle')"
                      >
                        {{ t("app.simulation.forensic.resetBtn") }}
                      </VeyButton>
                    </div>
                  </template>
                  <template v-else>
                    <VeyButton
                      type="primary"
                      size="small"
                      data-ui="start-forensic"
                      :loading="isTogglingPcap(toInstance(row).instanceId)"
                      :disabled="isTogglingPcap(toInstance(row).instanceId)"
                      @click="handleStartCapture(toInstance(row))"
                    >
                      {{ t("app.simulation.forensic.startBtn") }}
                    </VeyButton>
                  </template>
                </div>
              </template>
              <template #actions="{ row }">
                <VeyActionMenu
                  :label="t('common.actions')"
                  :actions="instanceActions(toInstance(row))"
                  :disabled="isUndeploying(toInstance(row).instanceId)"
                />
              </template>
              <template #empty>
                <div class="empty-placeholder">
                  {{ t("app.simulation.deployments.emptyTip") }}
                </div>
              </template>
            </VeyTable>
            <VeyLoading
              :loading="deploymentsLoading"
              cover
              data-ui="sim-deployments-loading"
            />
          </div>
        </div>
      </div>

      <!-- TAB 2: 规则整编 (Rules) -->
      <div
        v-if="activeTab === 'rules'"
        class="tab-content flex-column gap-layout"
      >
        <!-- 筛选检索工具栏 -->
        <div class="control-header flex-layout gap-layout flex-align-center">
          <div class="filter-item">
            <span class="label">{{
              t("app.simulation.rules.filters.name")
            }}</span>
            <VeyInput
              v-model="rulesFilter.name"
              :placeholder="t('app.simulation.rules.filters.placeholderName')"
              style="width: 180px"
            />
          </div>
          <div class="filter-item">
            <span class="label">{{
              t("app.simulation.rules.filters.cve")
            }}</span>
            <VeyInput
              v-model="rulesFilter.cve"
              :placeholder="t('app.simulation.rules.filters.placeholderCve')"
              style="width: 160px"
            />
          </div>
          <div class="filter-item">
            <span class="label">{{
              t("app.simulation.rules.filters.category")
            }}</span>
            <VeySelect
              v-model="rulesFilter.category"
              :options="categoryFilterOptions"
              style="width: 130px"
            />
          </div>
          <div class="filter-item">
            <span class="label">{{
              t("app.simulation.rules.filters.protocol")
            }}</span>
            <VeySelect
              v-model="rulesFilter.protocol"
              :options="protocolFilterOptions"
              style="width: 110px"
            />
          </div>

          <div class="rules-toolbar-actions">
            <VeyButton
              type="secondary"
              size="small"
              :loading="isUploadingPackage"
              @click="triggerPackageUpload"
            >
              {{
                currentPackage
                  ? t("app.simulation.rules.package.upgradeBtn")
                  : t("app.simulation.rules.package.importBtn")
              }}
            </VeyButton>
            <VeyButton type="primary" size="small" @click="openNewRuleDialog">
              + {{ t("app.simulation.rules.newBtn") }}
            </VeyButton>
            <input
              type="file"
              ref="packageFileInput"
              accept=".vprp"
              @change="handleUploadPackage"
              style="display: none"
            />
          </div>
        </div>

        <div class="main-panel flex-column flex-1" data-slot="content">
          <div
            ref="rulesTableRegionRef"
            class="table-body-region flex-1 overflow-auto"
          >
            <VeyTable
              :data="pagedRules"
              :columns="extendedRuleColumns"
              border
              data-ui="sim-rules-table"
            >
              <template #index="{ index }">
                {{ (rulesCurrentPage - 1) * rulesPageSize + index + 1 }}
              </template>
              <template #name="{ row }">
                <VeyTooltip
                  class="rule-name-tooltip"
                  :text="getRuleName(row)"
                  position="top"
                >
                  <span class="rule-table-name">{{ getRuleName(row) }}</span>
                </VeyTooltip>
              </template>
              <template #cve="{ row }">
                <span class="mono" v-if="row.cve">{{ row.cve }}</span>
                <span class="disabled-text" v-else>{{
                  t("app.simulation.rules.noCve")
                }}</span>
              </template>
              <template #category="{ row }">
                <VeyTag :type="getCategoryTagType(row.category)" size="small">
                  {{ getCategoryLabel(row.category) }}
                </VeyTag>
              </template>
              <template #protocol="{ row }">
                <VeyTag type="info" size="small">{{
                  row.protocol.toUpperCase()
                }}</VeyTag>
              </template>
              <template #actions="{ row }">
                <div class="table-actions">
                  <VeyButton
                    type="primary"
                    size="small"
                    @click="openDeployDialog(row)"
                  >
                    {{ t("app.simulation.rules.deployBtn") }}
                  </VeyButton>
                  <VeyButton
                    type="secondary"
                    size="small"
                    @click="openDetailDrawer(row)"
                  >
                    {{ t("common.details") }}
                  </VeyButton>
                  <VeyButton
                    type="danger"
                    size="small"
                    :disabled="row.id <= BUILTIN_RULE_MAX_ID"
                    @click="handleDeleteRule(row.id, getRuleName(row))"
                  >
                    {{ t("common.delete") }}
                  </VeyButton>
                </div>
              </template>
              <template #empty>
                <div
                  v-if="!currentPackage && rules.length === 0"
                  class="empty-placeholder flex-column flex-align-center gap-layout"
                  style="
                    padding: 60px 0;
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    gap: 16px;
                  "
                >
                  <div
                    style="
                      font-size: 14px;
                      color: var(--text-color-secondary, #666);
                      text-align: center;
                      max-width: 480px;
                      line-height: 1.6;
                    "
                  >
                    {{ t("app.simulation.rules.package.emptyGuide") }}
                  </div>
                  <div
                    class="flex-layout gap-layout flex-justify-center"
                    style="
                      display: flex;
                      gap: 12px;
                      justify-content: center;
                      margin-top: 8px;
                    "
                  >
                    <VeyButton
                      type="primary"
                      size="small"
                      :loading="isUploadingPackage"
                      @click="triggerPackageUpload"
                    >
                      {{ t("app.simulation.rules.package.importBtn") }}
                    </VeyButton>
                    <VeyButton
                      type="secondary"
                      size="small"
                      @click="openNewRuleDialog"
                    >
                      {{ t("app.simulation.rules.newBtn") }}
                    </VeyButton>
                  </div>
                </div>
                <div v-else class="empty-placeholder">
                  {{ t("app.simulation.rules.empty") }}
                </div>
              </template>
            </VeyTable>
            <VeyLoading
              :loading="rulesLoading"
              cover
              data-ui="sim-rules-loading"
            />
          </div>

          <!-- 分页器 -->
          <div
            class="pagination-bar border-top flex-layout flex-align-center flex-between"
            data-slot="footer"
          >
            <!-- 左侧规则库信息 -->
            <div
              v-if="currentPackage"
              class="flex-layout flex-align-center"
              style="
                font-size: 12px;
                color: #666;
                display: flex;
                align-items: center;
                gap: 16px;
              "
            >
              <div
                class="flex-layout flex-align-center"
                style="display: flex; align-items: center; gap: 8px"
              >
                <span style="font-weight: bold; color: var(--text-color, #333)">
                  {{ t("app.simulation.rules.package.current") }}:
                </span>
                <span
                  class="mono"
                  style="
                    color: var(--primary-color, #1890ff);
                    font-family: monospace;
                  "
                >
                  v{{ currentPackage.version }}
                </span>
              </div>
              <span
                style="
                  border-left: 1px solid #e0e0e0;
                  padding-left: 12px;
                  height: 12px;
                  display: inline-flex;
                  align-items: center;
                "
              >
                {{ t("app.simulation.rules.package.ruleCount") }}:
                {{ currentPackage.ruleCount }}
              </span>
              <span
                style="
                  border-left: 1px solid #e0e0e0;
                  padding-left: 12px;
                  height: 12px;
                  display: inline-flex;
                  align-items: center;
                "
              >
                {{ t("app.simulation.rules.package.importedAt") }}:
                {{ formatDateTime(currentPackage.importedAt) }}
              </span>
            </div>
            <div v-else style="font-size: 12px; color: #999">
              {{ t("app.simulation.rules.package.notImported") }}
            </div>

            <VeyPagination
              :current-page="rulesCurrentPage"
              :total-pages="rulesTotalPages"
              @page-change="(p) => (rulesCurrentPage = p)"
            />
          </div>
        </div>
      </div>
    </div>

    <!-- 弹窗：部署仿真服务 -->
    <VeyDialog
      :visible="isDeployDialogOpen"
      :title="t('app.simulation.deployments.deploySimulation')"
      width="500px"
      :close-on-click-overlay="!isDeploying"
      @close="closeDeployDialog"
    >
      <div
        class="dialog-detail-content flex-column gap-layout"
        data-ui="simulation-deploy-dialog"
      >
        <div
          class="detail-badge flex-layout gap-layout flex-align-center card-box"
          style="padding: 10px; margin-bottom: 12px"
        >
          <span
            style="
              font-weight: 600;
              font-size: 13px;
              color: var(--vdl-text-primary);
            "
            >{{ t("app.simulation.deployments.selectedRuleLabel") }}</span
          >
          <VeyTag type="info">{{ getRuleName(ruleToDeploy) }}</VeyTag>
        </div>

        <div class="form-group">
          <label>{{ t("app.simulation.deployments.port") }}</label>
          <VeyInput
            v-model="deployForm.port"
            data-ui="simulation-deploy-port-input"
            type="number"
            :placeholder="t('app.simulation.deployments.portPlaceholder')"
          />
        </div>
      </div>

      <template #footer>
        <VeyButton
          data-ui="simulation-deploy-cancel"
          type="secondary"
          :disabled="isDeploying"
          @click="closeDeployDialog"
        >
          {{ t("confirmation.cancel") }}
        </VeyButton>
        <VeyButton
          data-ui="simulation-deploy-confirm"
          type="primary"
          :disabled="!canConfirmDeploy"
          :loading="isDeploying"
          @click="executeDeploy"
        >
          {{ t("confirmation.confirm") }}
        </VeyButton>
      </template>
    </VeyDialog>

    <SimulationRuleDetailDialog
      :visible="isDetailDrawerOpen"
      :rule="ruleDetail"
      :capability="ruleDetailCapability"
      @close="isDetailDrawerOpen = false"
    />

    <!-- 弹窗：新建自定义规则 -->
    <VeyDialog
      :visible="isRuleDialogOpen"
      :title="t('app.simulation.rules.newBtn')"
      width="800px"
      @close="isRuleDialogOpen = false"
    >
      <div class="dialog-detail-content flex-column gap-layout">
        <!-- 基础信息 -->
        <div class="section-card card-box">
          <h4>{{ t("app.simulation.rules.title") }}</h4>
          <div class="form-group">
            <label>{{ t("app.simulation.rules.fields.name") }}</label>
            <VeyInput
              v-model="ruleForm.name"
              :placeholder="ruleNamePlaceholder"
            />
          </div>
          <div class="form-group">
            <label>{{ t("app.simulation.rules.fields.protocol") }}</label>
            <VeySelect
              v-model="ruleForm.protocol"
              :options="protocolOptions"
              data-ui="simulation-rule-protocol-select"
            />
          </div>
          <div class="form-group">
            <label>{{ t("app.simulation.rules.fields.defaultPort") }}</label>
            <VeyInput
              v-model="ruleForm.defaultPort"
              type="number"
              :placeholder="String(currentProtocolDefaultPort)"
            />
          </div>
          <div
            v-for="field in dynamicProtocolFields"
            :key="field.path"
            class="form-group"
          >
            <label>
              {{ t("app.simulation.rules.fields." + field.labelKey) }}
              <span v-if="field.required" aria-hidden="true">*</span>
            </label>
            <VeyInput
              v-model="dynamicFieldValues[field.path]"
              :type="
                field.secret
                  ? 'password'
                  : field.kind === 'number'
                    ? 'number'
                    : 'text'
              "
              :placeholder="
                field.kind === 'string_list'
                  ? t('app.simulation.rules.editor.listHint')
                  : field.labelKey
              "
            />
          </div>
          <div v-if="showBannerField" class="form-group">
            <label>{{ t("app.simulation.rules.fields.banner") }}</label>
            <VeyInput
              v-model="ruleForm.banner"
              :placeholder="t('app.simulation.rules.fields.bannerPlaceholder')"
            />
          </div>
          <div v-if="isMailRuleForm" class="form-group">
            <label>{{ t("app.simulation.rules.fields.hostname") }}</label>
            <VeyInput
              v-model="ruleForm.hostname"
              :placeholder="
                t('app.simulation.rules.fields.hostnamePlaceholder')
              "
            />
          </div>
          <div v-if="isHttpRuleForm" class="form-group">
            <label>{{ t("app.simulation.rules.fields.serverHeader") }}</label>
            <VeyInput
              v-model="ruleForm.serverHeader"
              :placeholder="
                t('app.simulation.rules.fields.serverHeaderPlaceholder')
              "
            />
          </div>
          <div v-if="isHttpRuleForm" class="form-group">
            <label>{{ t("app.simulation.rules.fields.html") }}</label>
            <textarea
              v-model="ruleForm.html"
              class="textarea-input"
              :placeholder="t('app.simulation.rules.fields.htmlPlaceholder')"
            ></textarea>
          </div>
          <div v-if="isRedisRuleForm" class="form-group">
            <label>{{ t("app.simulation.rules.fields.requireAuth") }}</label>
            <div class="inline-check-row">
              <VeyCheckbox
                :model-value="ruleForm.requireAuth"
                @change="(val) => (ruleForm.requireAuth = val)"
              />
              <span>{{
                t("app.simulation.rules.fields.requireAuthHint")
              }}</span>
            </div>
          </div>
          <div
            v-if="isRedisRuleForm && ruleForm.requireAuth"
            class="form-group"
          >
            <label>{{ t("app.simulation.rules.fields.password") }}</label>
            <VeyInput
              v-model="ruleForm.password"
              :placeholder="
                t('app.simulation.rules.fields.passwordPlaceholder')
              "
            />
          </div>
          <div v-if="ruleForm.protocol === 'ftp'" class="form-group">
            <label>{{ t("app.simulation.rules.fields.serverName") }}</label>
            <VeyInput
              v-model="ruleForm.serverName"
              :placeholder="
                t('app.simulation.rules.fields.serverNamePlaceholder')
              "
            />
          </div>
          <div
            v-if="ruleForm.protocol === 'ftp' || ruleForm.protocol === 'mqtt'"
            class="form-group"
          >
            <label>{{ t("app.simulation.rules.fields.allowAnonymous") }}</label>
            <div class="inline-check-row">
              <VeyCheckbox
                :model-value="ruleForm.allowAnonymous"
                @change="(val) => (ruleForm.allowAnonymous = val)"
              />
              <span>{{
                t("app.simulation.rules.fields.allowAnonymousHint")
              }}</span>
            </div>
          </div>
          <div v-if="ruleForm.protocol === 'rdp'" class="form-group">
            <label>{{ t("app.simulation.rules.fields.rdpFlags") }}</label>
            <VeyInput
              v-model="ruleForm.rdpFlags"
              type="number"
              :placeholder="
                t('app.simulation.rules.fields.rdpFlagsPlaceholder')
              "
            />
          </div>
        </div>

        <div class="section-card card-box">
          <div class="drawer-card-header" data-slot="header">
            <h4>{{ t("app.simulation.rules.editor.title") }}</h4>
            <div class="flex-layout gap-layout">
              <VeyButton
                :type="ruleEditorMode === 'guided' ? 'primary' : 'secondary'"
                size="small"
                @click="setRuleEditorMode('guided')"
              >
                {{ t("app.simulation.rules.editor.guided") }}
              </VeyButton>
              <VeyButton
                :type="ruleEditorMode === 'json' ? 'primary' : 'secondary'"
                size="small"
                @click="setRuleEditorMode('json')"
              >
                {{ t("app.simulation.rules.editor.json") }}
              </VeyButton>
            </div>
          </div>
          <div v-if="ruleEditorMode === 'json'" class="form-group">
            <textarea
              v-model="advancedRuleJson"
              class="textarea-input"
              rows="14"
              spellcheck="false"
            ></textarea>
          </div>
          <p v-else class="editor-hint">
            {{ t("app.simulation.rules.editor.guidedHint") }}
          </p>
        </div>

        <!-- 漏洞路由添加 -->
        <div
          v-if="ruleEditorMode === 'guided' && isHttpRuleForm"
          class="section-card card-box"
        >
          <div class="drawer-card-header" data-slot="header">
            <h4>{{ t("app.simulation.rules.exploitPaths.title") }}</h4>
            <VeyButton type="secondary" size="small" @click="addExploitPath">
              + {{ t("app.simulation.rules.exploitPaths.addBtn") }}
            </VeyButton>
          </div>

          <div class="exploit-paths-list">
            <div
              v-for="(ep, idx) in exploitPaths"
              :key="idx"
              class="exploit-path-card card-box border-dashed"
            >
              <div class="card-title flex-layout flex-between">
                <h5>
                  {{ t("app.simulation.rules.exploitPaths.routeFeature") }} #{{
                    idx + 1
                  }}
                </h5>
                <VeyButton
                  type="danger"
                  size="small"
                  @click="removeExploitPath(idx)"
                >
                  {{ t("common.delete") }}
                </VeyButton>
              </div>
              <div class="form-group">
                <label>{{ t("app.simulation.rules.exploitPaths.path") }}</label>
                <VeyInput
                  v-model="ep.path"
                  :placeholder="
                    t('app.simulation.rules.exploitPaths.pathPlaceholder')
                  "
                />
              </div>
              <div class="flex-layout gap-layout">
                <div class="form-group flex-1">
                  <label>{{
                    t("app.simulation.rules.exploitPaths.method")
                  }}</label>
                  <VeySelect
                    v-model="ep.triggerMethod"
                    :options="methodOptions"
                  />
                </div>
                <div class="form-group flex-1">
                  <label>{{
                    t("app.simulation.rules.exploitPaths.status")
                  }}</label>
                  <VeyInput
                    v-model="ep.responseStatus"
                    :placeholder="
                      t('app.simulation.rules.exploitPaths.statusPlaceholder')
                    "
                  />
                </div>
              </div>
              <div class="form-group">
                <label>{{ t("app.simulation.rules.exploitPaths.body") }}</label>
                <textarea
                  v-model="ep.responseBody"
                  class="textarea-input-sm"
                  :placeholder="
                    t('app.simulation.rules.exploitPaths.bodyPlaceholder')
                  "
                ></textarea>
              </div>
            </div>
          </div>
        </div>

        <div
          v-if="ruleEditorMode === 'guided' && isKeyValueRuleForm"
          class="section-card card-box"
        >
          <div class="drawer-card-header" data-slot="header">
            <h4>{{ keyValueText("title") }}</h4>
            <VeyButton type="secondary" size="small" @click="addRedisKey">
              + {{ keyValueText("addBtn") }}
            </VeyButton>
          </div>
          <div class="protocol-list">
            <div
              v-for="(item, idx) in redisKeys"
              :key="idx"
              class="protocol-list-item card-box border-dashed"
            >
              <div class="card-title flex-layout flex-between">
                <h5>{{ keyValueText("itemTitle") }} #{{ idx + 1 }}</h5>
                <VeyButton
                  type="danger"
                  size="small"
                  @click="removeRedisKey(idx)"
                >
                  {{ t("common.delete") }}
                </VeyButton>
              </div>
              <div class="flex-layout gap-layout">
                <div class="form-group flex-1">
                  <label>{{ keyValueText("key") }}</label>
                  <VeyInput
                    v-model="item.key"
                    :placeholder="keyValueText('keyPlaceholder')"
                  />
                </div>
                <div class="form-group flex-1">
                  <label>{{ keyValueText("value") }}</label>
                  <VeyInput
                    v-model="item.value"
                    :placeholder="keyValueText('valuePlaceholder')"
                  />
                </div>
              </div>
            </div>
          </div>
        </div>

        <div
          v-if="ruleEditorMode === 'guided' && isCredentialRuleForm"
          class="section-card card-box"
        >
          <div class="drawer-card-header" data-slot="header">
            <h4>{{ t("app.simulation.rules.credentials.title") }}</h4>
            <VeyButton type="secondary" size="small" @click="addCredential">
              + {{ t("app.simulation.rules.credentials.addBtn") }}
            </VeyButton>
          </div>
          <div class="protocol-list">
            <div
              v-for="(item, idx) in credentials"
              :key="idx"
              class="protocol-list-item card-box border-dashed"
            >
              <div class="card-title flex-layout flex-between">
                <h5>
                  {{ t("app.simulation.rules.credentials.itemTitle") }} #{{
                    idx + 1
                  }}
                </h5>
                <VeyButton
                  type="danger"
                  size="small"
                  @click="removeCredential(idx)"
                >
                  {{ t("common.delete") }}
                </VeyButton>
              </div>
              <div class="flex-layout gap-layout">
                <div class="form-group flex-1">
                  <label>{{
                    t("app.simulation.rules.credentials.username")
                  }}</label>
                  <VeyInput
                    v-model="item.username"
                    :placeholder="
                      t('app.simulation.rules.credentials.usernamePlaceholder')
                    "
                  />
                </div>
                <div class="form-group flex-1">
                  <label>{{
                    t("app.simulation.rules.credentials.password")
                  }}</label>
                  <VeyInput
                    v-model="item.password"
                    :placeholder="
                      t('app.simulation.rules.credentials.passwordPlaceholder')
                    "
                  />
                </div>
              </div>
              <div v-if="isMailRuleForm" class="form-group">
                <label>{{
                  t("app.simulation.rules.credentials.displayName")
                }}</label>
                <VeyInput
                  v-model="item.displayName"
                  :placeholder="
                    t('app.simulation.rules.credentials.displayNamePlaceholder')
                  "
                />
              </div>
            </div>
          </div>
        </div>

        <div
          v-if="ruleEditorMode === 'guided' && isMailRuleForm"
          class="section-card card-box"
        >
          <div class="drawer-card-header" data-slot="header">
            <h4>{{ t("app.simulation.rules.mailMessages.title") }}</h4>
            <VeyButton type="secondary" size="small" @click="addMailMessage">
              + {{ t("app.simulation.rules.mailMessages.addBtn") }}
            </VeyButton>
          </div>
          <div class="protocol-list">
            <div
              v-for="(item, idx) in mailMessages"
              :key="idx"
              class="protocol-list-item card-box border-dashed"
            >
              <div class="card-title flex-layout flex-between">
                <h5>
                  {{ t("app.simulation.rules.mailMessages.itemTitle") }} #{{
                    idx + 1
                  }}
                </h5>
                <VeyButton
                  type="danger"
                  size="small"
                  @click="removeMailMessage(idx)"
                >
                  {{ t("common.delete") }}
                </VeyButton>
              </div>
              <div class="flex-layout gap-layout">
                <div class="form-group flex-1">
                  <label>{{
                    t("app.simulation.rules.mailMessages.from")
                  }}</label>
                  <VeyInput
                    v-model="item.from"
                    :placeholder="
                      t('app.simulation.rules.mailMessages.fromPlaceholder')
                    "
                  />
                </div>
                <div class="form-group flex-1">
                  <label>{{ t("app.simulation.rules.mailMessages.to") }}</label>
                  <VeyInput
                    v-model="item.to"
                    :placeholder="
                      t('app.simulation.rules.mailMessages.toPlaceholder')
                    "
                  />
                </div>
              </div>
              <div class="form-group">
                <label>{{
                  t("app.simulation.rules.mailMessages.subject")
                }}</label>
                <VeyInput
                  v-model="item.subject"
                  :placeholder="
                    t('app.simulation.rules.mailMessages.subjectPlaceholder')
                  "
                />
              </div>
              <div class="form-group">
                <label>{{ t("app.simulation.rules.mailMessages.body") }}</label>
                <textarea
                  v-model="item.body"
                  class="textarea-input-sm"
                  :placeholder="
                    t('app.simulation.rules.mailMessages.bodyPlaceholder')
                  "
                ></textarea>
              </div>
            </div>
          </div>
        </div>

        <div
          v-if="
            ruleEditorMode === 'guided' && (isRedisRuleForm || isMailRuleForm)
          "
          class="section-card card-box"
        >
          <div class="drawer-card-header" data-slot="header">
            <h4>{{ t("app.simulation.rules.commandResponses.title") }}</h4>
            <VeyButton
              type="secondary"
              size="small"
              @click="addCommandResponse"
            >
              + {{ t("app.simulation.rules.commandResponses.addBtn") }}
            </VeyButton>
          </div>
          <div class="protocol-list">
            <div
              v-for="(item, idx) in commandResponses"
              :key="idx"
              class="protocol-list-item card-box border-dashed"
            >
              <div class="card-title flex-layout flex-between">
                <h5>
                  {{ t("app.simulation.rules.commandResponses.itemTitle") }} #{{
                    idx + 1
                  }}
                </h5>
                <VeyButton
                  type="danger"
                  size="small"
                  @click="removeCommandResponse(idx)"
                >
                  {{ t("common.delete") }}
                </VeyButton>
              </div>
              <div class="flex-layout gap-layout">
                <div class="form-group flex-1">
                  <label>{{
                    t("app.simulation.rules.commandResponses.command")
                  }}</label>
                  <VeyInput
                    v-model="item.command"
                    :placeholder="
                      t(
                        'app.simulation.rules.commandResponses.commandPlaceholder',
                      )
                    "
                  />
                </div>
                <div class="form-group flex-1">
                  <label>{{
                    t("app.simulation.rules.commandResponses.argsContains")
                  }}</label>
                  <VeyInput
                    v-model="item.argsContains"
                    :placeholder="
                      t(
                        'app.simulation.rules.commandResponses.argsContainsPlaceholder',
                      )
                    "
                  />
                </div>
              </div>
              <div class="form-group">
                <label>{{
                  t("app.simulation.rules.commandResponses.response")
                }}</label>
                <textarea
                  v-model="item.response"
                  class="textarea-input-sm"
                  :placeholder="
                    t(
                      'app.simulation.rules.commandResponses.responsePlaceholder',
                    )
                  "
                ></textarea>
              </div>
            </div>
          </div>
        </div>
      </div>

      <template #footer>
        <div class="flex-layout flex-end gap-layout">
          <VeyButton type="secondary" @click="isRuleDialogOpen = false">
            {{ t("confirmation.cancel") }}
          </VeyButton>
          <VeyButton
            type="primary"
            :disabled="isCreatingRule"
            @click="handleCreateRule"
          >
            {{ t("common.create") }}
          </VeyButton>
        </div>
      </template>
    </VeyDialog>

    <InstanceAuditDialog
      :visible="auditInstance !== null"
      :instance="auditInstance"
      @close="auditInstance = null"
    />

    <VeyModal
      :visible="confirmationState.visible"
      :title="confirmationState.title"
      :message="confirmationState.message"
      :confirm-text="confirmationState.confirmText"
      :cancel-text="confirmationState.cancelText"
      type="danger"
      @confirm="resolveConfirmation(true)"
      @cancel="resolveConfirmation(false)"
    />

    <!-- 加载等待遮罩 -->
    <VeyLoading :loading="isLoading" cover />
  </div>
</template>

<style scoped>
.simulation-dashboard {
  position: relative;
  height: 100%;
  padding: var(--vdl-space-4);
  background: var(--vdl-bg-canvas);
  box-sizing: border-box;
  display: flex;
  flex-direction: column;
  gap: var(--vdl-space-4);
  min-height: 0;
  overflow: hidden;
}

.dashboard-header {
  flex-shrink: 0;
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-bottom: 1px solid rgba(148, 163, 184, 0.12);
  min-height: 42px;
}

/* 主导航直接消费组件库材质，避免自绘实色选中块。 */
:deep([data-ui="simulation-tabs"] .vl-tabs-nav) {
  border-bottom: 0;
}

/* Body */
.dashboard-body {
  flex: 1;
  min-height: 0;
  display: flex;
  flex-direction: column;
}

.tab-content {
  flex: 1;
  min-height: 0;
}

/* 常用布局 */
.flex-layout {
  display: flex;
}

.flex-column {
  display: flex;
  flex-direction: column;
}

.flex-1 {
  flex: 1;
  min-height: 0;
}

.flex-2 {
  flex: 2;
  min-height: 0;
}

.flex-center {
  justify-content: center;
  align-items: center;
}

.flex-end {
  justify-content: flex-end;
}

.flex-between {
  justify-content: space-between;
}

.flex-align-center {
  align-items: center;
}

.gap-layout {
  gap: var(--vdl-space-4);
}

.gap-2 {
  gap: var(--vdl-space-2);
}

.border-bottom {
  border-bottom: 1px solid rgba(148, 163, 184, 0.12);
}

.border-top {
  border-top: 1px solid rgba(148, 163, 184, 0.12);
}

.overflow-auto {
  overflow: auto;
  min-height: 0;
}

.main-panel {
  flex: 1;
  min-width: 0;
  min-height: 0;
  overflow: hidden;
}

.main-panel > .overflow-auto {
  display: flex;
  flex-direction: column;
}

.table-body-region {
  position: relative;
}

:deep([data-ui="sim-rules-table"] .vl-table) {
  table-layout: fixed;
}

:deep([data-ui="sim-rules-table"] .vl-table-cell .vl-cell) {
  white-space: nowrap;
}

.rule-name-tooltip,
.rule-table-name {
  display: block;
  min-width: 0;
  max-width: 100%;
}

.rule-table-name {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.panel-header {
  padding: var(--vdl-space-3) var(--vdl-space-4);
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-shrink: 0;
}

.panel-header h3 {
  margin: 0;
  font-size: 16px;
  font-weight: 600;
  color: var(--vdl-text-primary);
}

.table-actions {
  display: flex;
  gap: var(--vdl-space-2);
  justify-content: center;
}

.status-cell {
  display: grid;
  gap: var(--vdl-space-1);
  justify-items: center;
  min-width: 0;
}

.status-error-message {
  display: block;
  max-width: 180px;
  color: var(--vdl-danger);
  font-size: 12px;
  line-height: 1.35;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  cursor: help;
}

.card-box {
  background: var(--vdl-bg-card);
  border: 1px solid rgba(148, 163, 184, 0.08);
  border-radius: var(--vdl-radius-md);
  padding: var(--vdl-space-4);
}

.border-dashed {
  border-style: dashed;
}

.param-row {
  display: flex;
  margin-bottom: var(--vdl-space-2);
  font-size: 13px;
}

.param-row .label {
  color: var(--vdl-text-muted);
  width: 140px;
  flex-shrink: 0;
}

.param-row .val {
  color: var(--vdl-text-primary);
}

.mono {
  font-family: var(--vdl-font-mono);
}

.code-preview {
  margin: 0;
  background: rgba(8, 14, 24, 0.5);
  padding: var(--vdl-space-3);
  border-radius: var(--vdl-radius-sm);
  color: var(--vdl-text-secondary);
  font-family: var(--vdl-font-mono);
  font-size: 12px;
  max-height: 240px;
  overflow: auto;
  white-space: pre-wrap;
  word-break: break-all;
}

.empty-placeholder {
  text-align: center;
  padding: 32px 16px;
  color: var(--vdl-text-subtle);
  font-size: 13px;
}

/* 顶部选择过滤栏 */
.control-header {
  padding: var(--vdl-space-3) var(--vdl-space-4);
  display: flex;
  justify-content: space-between;
  align-items: center;
  border: 1px solid var(--vdl-border-subtle);
  border-radius: var(--vdl-radius-lg);
}

.filter-item {
  display: flex;
  align-items: center;
  gap: var(--vdl-space-2);
}

.filter-item .label {
  font-size: 13px;
  font-weight: 500;
  color: var(--vdl-text-secondary);
}

.rules-toolbar-actions {
  margin-left: auto;
  display: inline-flex;
  align-items: center;
  gap: var(--vdl-space-2);
  flex-wrap: wrap;
}

/* 分页条 */
.pagination-bar {
  padding: var(--vdl-space-3) var(--vdl-space-4);
  flex-shrink: 0;
}

.disabled-text {
  color: var(--vdl-text-subtle);
  font-size: 12px;
}

.dialog-panel {
  width: 500px;
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
  border-radius: var(--vdl-radius-lg);
  overflow: hidden;
  animation: scaleUp 0.2s cubic-bezier(0.16, 1, 0.3, 1) forwards;
}

.table-scroll-container {
  max-height: 220px;
  overflow-y: auto;
  border-radius: var(--vdl-radius-md);
  border: 1px solid var(--vdl-border-subtle);
}

.code-preview-container {
  max-height: 180px;
  overflow: auto;
  border-radius: var(--vdl-radius-md);
  border: 1px solid var(--vdl-border-subtle);
  background-color: var(--vdl-bg-input);
}

.code-preview {
  margin: 0;
  padding: var(--vdl-space-3);
  font-family: var(--vdl-font-mono);
  font-size: var(--vdl-font-body-sm);
  color: var(--vdl-text-secondary);
  white-space: pre-wrap;
  word-break: break-all;
}

.section-header-row {
  margin-bottom: 14px;
}

.section-header-row h4 {
  margin: 0 !important;
}

.mini-tab-box {
  display: flex;
  background-color: rgba(8, 14, 24, 0.6);
  border: 1px solid var(--vdl-border-subtle);
  border-radius: var(--vdl-radius-md);
  padding: 2px;
  box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.3);
}

.mini-tab-btn {
  background: transparent;
  border: none;
  color: var(--vdl-text-muted);
  font-size: 12px;
  font-weight: 600;
  padding: 4px 12px;
  border-radius: var(--vdl-radius-sm);
  cursor: pointer;
  transition: all 0.15s cubic-bezier(0.16, 1, 0.3, 1);
}

.mini-tab-btn:hover {
  color: var(--vdl-text-primary);
  background-color: rgba(148, 163, 184, 0.05);
}

.mini-tab-btn.active {
  background-color: var(--vdl-bg-card);
  color: var(--vdl-primary);
  box-shadow: 0 2px 5px rgba(0, 0, 0, 0.3);
}

@keyframes scaleUp {
  from {
    transform: scale(0.9);
    opacity: 0;
  }
  to {
    transform: scale(1);
    opacity: 1;
  }
}

.section-card h4 {
  margin: 0 0 12px;
  font-size: 14px;
  color: var(--vdl-primary);
  font-weight: 600;
}

/* Form Styles inside Drawer */
.form-group {
  margin-bottom: var(--vdl-space-3);
  display: flex;
  flex-direction: column;
  gap: var(--vdl-space-2);
}

.form-group label {
  font-size: 12px;
  color: var(--vdl-text-secondary);
  font-weight: 500;
}

.endpoint-summary {
  white-space: nowrap;
}

.textarea-input {
  width: 100%;
  height: 140px;
  padding: var(--vdl-space-2);
  border: 1px solid var(--vdl-border-default);
  border-radius: var(--vdl-radius-md);
  background: var(--vdl-bg-input);
  color: var(--vdl-text-primary);
  box-sizing: border-box;
  font-family: var(--vdl-font-mono);
  font-size: 12px;
  resize: vertical;
}

.textarea-input-sm {
  width: 100%;
  height: 90px;
  padding: var(--vdl-space-2);
  border: 1px solid var(--vdl-border-default);
  border-radius: var(--vdl-radius-md);
  background: var(--vdl-bg-input);
  color: var(--vdl-text-primary);
  box-sizing: border-box;
  font-family: var(--vdl-font-mono);
  font-size: 12px;
  resize: vertical;
}

.drawer-card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--vdl-space-3);
}

.drawer-card-header h4 {
  margin: 0;
  font-size: 14px;
  color: var(--vdl-primary);
  font-weight: 600;
}

.exploit-paths-list {
  display: flex;
  flex-direction: column;
  gap: var(--vdl-space-4);
}

.protocol-list {
  display: flex;
  flex-direction: column;
  gap: var(--vdl-space-4);
}

.protocol-list-item {
  position: relative;
}

.protocol-list-item h5 {
  margin: 0 0 12px;
  font-size: 13px;
  color: var(--vdl-text-primary);
  font-weight: 600;
}

.inline-check-row {
  display: flex;
  align-items: center;
  gap: var(--vdl-space-2);
  color: var(--vdl-text-secondary);
  font-size: 13px;
}

.exploit-path-card {
  position: relative;
}

.exploit-path-card h5 {
  margin: 0 0 12px;
  font-size: 13px;
  color: var(--vdl-text-primary);
  font-weight: 600;
}

/* Forensic Capture Styles */
.forensic-cell {
  display: flex;
  justify-content: center;
  align-items: center;
}

.capturing-wrapper {
  display: flex;
  align-items: center;
  gap: 8px;
}

.ready-wrapper {
  display: flex;
  align-items: center;
  gap: 8px;
}

.download-btn-link {
  text-decoration: none;
  display: inline-flex;
}

.rule-name-cell {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: var(--vdl-space-2);
}

.rule-link-text {
  color: var(--vdl-primary);
  text-decoration: none;
  cursor: pointer;
  transition: color 0.15s ease;
}

.rule-link-text:hover {
  text-decoration: underline;
  opacity: 0.85;
}

.capturing-row-indicator {
  width: 7px;
  height: 7px;
  background-color: var(--vdl-danger);
  border-radius: var(--vdl-radius-pill);
  display: inline-block;
  position: relative;
  flex-shrink: 0;
  box-shadow: 0 0 0 0 rgba(255, 94, 122, 0.7);
  animation: pulse-recording 1.2s infinite cubic-bezier(0.4, 0, 0.6, 1);
}

@keyframes pulse-recording {
  0% {
    transform: scale(0.9);
    box-shadow: 0 0 0 0 rgba(255, 94, 122, 0.6);
  }
  60% {
    transform: scale(1.15);
    box-shadow: 0 0 0 5px rgba(255, 94, 122, 0);
  }
  100% {
    transform: scale(0.9);
    box-shadow: 0 0 0 0 rgba(255, 94, 122, 0);
  }
}

.live-pulse-bars {
  display: flex;
  align-items: flex-end;
  gap: 3px;
  height: 14px;
  padding-right: 4px;
  flex-shrink: 0;
}

.pulse-bar {
  width: 2px;
  height: 3px;
  background-color: var(--vdl-primary);
  border-radius: var(--vdl-radius-xs);
  animation: pulse-jump 0.8s infinite ease-in-out alternate;
}

.pulse-bar:nth-child(1) {
  animation-delay: 0.1s;
  height: 5px;
}
.pulse-bar:nth-child(2) {
  animation-delay: 0.3s;
  height: 9px;
}
.pulse-bar:nth-child(3) {
  animation-delay: 0.5s;
  height: 4px;
}
.pulse-bar:nth-child(4) {
  animation-delay: 0.2s;
  height: 7px;
}

@keyframes pulse-jump {
  0% {
    height: 3px;
    transform: scaleY(1);
    background-color: var(--vdl-primary);
  }
  100% {
    height: 14px;
    transform: scaleY(1.2);
    background-color: var(--vdl-secondary);
  }
}

.download-pulse-btn {
  position: relative;
  animation: button-breath 2s infinite ease-in-out;
  border-color: var(--vdl-primary) !important;
}

@keyframes button-breath {
  0% {
    box-shadow: 0 0 0 0 rgba(0, 200, 255, 0.4);
  }
  50% {
    box-shadow: 0 0 10px 3px rgba(0, 200, 255, 0.15);
  }
  100% {
    box-shadow: 0 0 0 0 rgba(0, 200, 255, 0);
  }
}
</style>

<style>
/* 优化超长审计文本在气泡提示中的折行显示 */
body .vl-tooltip-content {
  max-width: 450px;
  white-space: normal !important;
  word-break: break-all;
}
</style>
