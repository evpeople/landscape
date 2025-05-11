<script setup lang="ts">
import { computed } from "vue";
import { ExhibitType } from "@/lib/sys";

import SourceProgress from "@/components/SouceProgress.vue";
import { useSysInfo } from "@/stores/systeminfo";
import { useI18n } from "vue-i18n";

const { t } = useI18n({ useScope: "global" });

let sysinfo = useSysInfo();

const brand = computed(() => {
  let cpu = sysinfo.router_status.cpus[0];
  if (cpu) {
    return `${cpu.brand} @ ${(cpu.frequency / 1000).toFixed(2)} `;
  }
  return "N/A";
});

const load_avg = computed(() => {
  return sysinfo.router_status.load_avg;
});
</script>
<template>
  <!-- {{ sysinfo.router_status.cpus[0] }} -->
  <n-card content-style="display: flex; max-height: 240px;">
    <template #header> CPU</template>
    <n-flex style="flex: 1" vertical justify="space-between">
      <n-flex vertical justify="space-between">
        <n-flex justify="space-between">
          <n-flex>{{ t("total_cpu_usage") }}</n-flex>
          <n-flex>
            {{ sysinfo.router_status.global_cpu_info.toFixed(1) }} %
          </n-flex>
        </n-flex>

        <n-flex justify="space-between">
          <n-flex>{{ t("average_load") }}</n-flex>
          <n-flex>
            {{ `${load_avg.one} / ${load_avg.five} / ${load_avg.fifteen}` }}
          </n-flex>
        </n-flex>
      </n-flex>

      <n-flex
        v-if="sysinfo.router_status.cpus.length <= 4"
        style="overflow: hidden"
      >
        <n-scrollbar>
          <n-flex>
            <n-popover
              v-for="each_cpu of sysinfo.router_status.cpus"
              :key="each_cpu.name"
              trigger="hover"
            >
              <template #trigger>
                <SourceProgress
                  :exhibit_type="ExhibitType.Line"
                  :value="each_cpu.usage / 100"
                />
              </template>
              <span
                >{{ each_cpu.name }}: {{ each_cpu.brand }} @
                {{ each_cpu.frequency }}</span
              >
            </n-popover>
          </n-flex>
        </n-scrollbar>
      </n-flex>

      <n-grid
        v-else-if="sysinfo.router_status.cpus.length <= 8"
        :cols="2"
        :x-gap="12"
        :y-gap="12"
      >
        <n-gi
          v-for="each_cpu of sysinfo.router_status.cpus"
          :key="each_cpu.name"
        >
          <n-popover trigger="hover">
            <template #trigger>
              <SourceProgress
                :exhibit_type="ExhibitType.Line"
                :value="each_cpu.usage / 100"
              />
            </template>
            <span
              >{{ each_cpu.name }}: {{ each_cpu.brand }} @
              {{ each_cpu.frequency }}</span
            >
          </n-popover>
        </n-gi>
      </n-grid>

      <n-grid
        v-else-if="sysinfo.router_status.cpus.length <= 12"
        :cols="3"
        :x-gap="12"
        :y-gap="12"
      >
        <n-gi
          v-for="each_cpu of sysinfo.router_status.cpus"
          :key="each_cpu.name"
        >
          <n-popover trigger="hover">
            <template #trigger>
              <SourceProgress
                :exhibit_type="ExhibitType.Line"
                :value="each_cpu.usage / 100"
              />
            </template>
            <span
              >{{ each_cpu.name }}: {{ each_cpu.brand }} @
              {{ each_cpu.frequency }}</span
            >
          </n-popover>
        </n-gi>
      </n-grid>

      <!-- 当 CPU > 12 时 -->
      <n-grid v-else :cols="4" :x-gap="12" :y-gap="12">
        <n-gi
          v-for="each_cpu of sysinfo.router_status.cpus"
          :key="each_cpu.name"
        >
          <n-popover trigger="hover">
            <template #trigger>
              <SourceProgress
                :exhibit_type="ExhibitType.Line"
                :value="each_cpu.usage / 100"
              />
            </template>
            <span
              >{{ each_cpu.name }}: {{ each_cpu.brand }} @
              {{ each_cpu.frequency }}</span
            >
          </n-popover>
        </n-gi>
      </n-grid>
    </n-flex>
    <!-- {{ sysinfo.cpus }} -->
  </n-card>
</template>
