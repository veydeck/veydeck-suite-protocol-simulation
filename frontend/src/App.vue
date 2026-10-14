<script setup lang="ts">
import { onBeforeUnmount, ref } from "vue";
import { VeyGlassProvider } from "@veydeck/vue";
import SimulationView from "./apps/views/SimulationView.vue";
import { suiteBridge } from "./suite-bridge";

/** 主控下发的材质偏好；独立运行及旧载荷默认开启。 */
const glassEnabled = ref(suiteBridge.getThemeSnapshot().glassEnabled);
const unsubscribeTheme = suiteBridge.subscribeTheme((theme) => {
  glassEnabled.value = theme.glassEnabled;
});

onBeforeUnmount(unsubscribeTheme);
</script>

<template>
  <VeyGlassProvider :glass="glassEnabled">
    <SimulationView />
  </VeyGlassProvider>
</template>
