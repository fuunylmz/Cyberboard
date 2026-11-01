<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import type { UsageRow } from '@cyberboard/types'
import StatePanel from '@cyberboard/ui/components/StatePanel.vue'
import { adminApi, getApiErrorMessage } from '../api'

const pageSize = 20
const page = ref(1)
const total = ref(0)
const rows = ref<UsageRow[]>([])
const loading = ref(true)
const error = ref('')
const filters = reactive({ userId: '', nodeId: '', startTime: '', endTime: '' })

function toIsoDateTime(value: string) {
  if (!value) return undefined
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString()
}

function formatBytes(bytes: number) {
  if (!Number.isFinite(bytes)) return '—'
  if (bytes < 1024) return `${bytes} B`
  const units = ['KiB', 'MiB', 'GiB', 'TiB', 'PiB']
  let value = bytes
  let unit = -1
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit += 1 }
  return `${value.toLocaleString('zh-CN', { maximumFractionDigits: value >= 100 ? 0 : 1 })} ${units[unit]}`
}

function formatDate(value: string) {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString('zh-CN')
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    const result = await adminApi.listUsage({
      userId: filters.userId.trim() || undefined,
      nodeId: filters.nodeId.trim() || undefined,
      startTime: toIsoDateTime(filters.startTime),
      endTime: toIsoDateTime(filters.endTime),
      page: page.value,
      pageSize,
    })
    rows.value = result.items
    total.value = result.total
  } catch (cause) {
    rows.value = []
    total.value = 0
    error.value = getApiErrorMessage(cause)
  } finally {
    loading.value = false
  }
}

function search() {
  page.value = 1
  void load()
}

function clearFilters() {
  Object.assign(filters, { userId: '', nodeId: '', startTime: '', endTime: '' })
  search()
}

function previousPage() {
  if (page.value <= 1) return
  page.value -= 1
  void load()
}

function nextPage() {
  if (page.value * pageSize >= total.value) return
  page.value += 1
  void load()
}

onMounted(load)
</script>

<template>
  <div class="page-heading">
    <div><p class="eyebrow">流量与计费</p><h1>用量</h1><p>按用户与节点查看所选时间区间内的流量聚合。</p></div>
    <button class="button button--secondary" type="button" :disabled="loading" @click="load">{{ loading ? '加载中…' : '刷新' }}</button>
  </div>

  <section class="panel">
    <form class="usage-filters" @submit.prevent="search">
      <label>开始时间<input v-model="filters.startTime" type="datetime-local" /></label>
      <label>结束时间<input v-model="filters.endTime" type="datetime-local" /></label>
      <label>用户 ID<input v-model="filters.userId" type="text" inputmode="text" placeholder="可选" /></label>
      <label>节点 ID<input v-model="filters.nodeId" type="text" inputmode="text" placeholder="可选" /></label>
      <div class="usage-filter-actions"><button class="primary-button" type="submit" :disabled="loading">查询</button><button class="button button--secondary" type="button" :disabled="loading" @click="clearFilters">清除</button></div>
    </form>

    <StatePanel v-if="loading" title="正在加载用量" description="正在读取租户内的用户与节点流量聚合。" />
    <StatePanel v-else-if="error" title="用量加载失败" :description="error" action-label="重试" @action="load" />
    <StatePanel v-else-if="!rows.length" title="暂无用量" description="当前筛选条件没有匹配的聚合记录。" action-label="清除筛选" @action="clearFilters" />
    <div v-else class="table-wrap">
      <table>
        <thead><tr><th>用户邮箱</th><th>节点</th><th>总流量</th><th>下载</th><th>上传</th><th>统计区间</th><th>事件数</th></tr></thead>
        <tbody>
          <tr v-for="(row, index) in rows" :key="`${row.userId}:${row.nodeId ?? 'no-node'}:${row.periodStart}:${row.periodEnd}:${index}`">
            <td><strong>{{ row.username || '未知用户' }}</strong><small class="mono">{{ row.userId }}</small></td>
            <td class="mono">{{ row.nodeId ?? '—' }}</td>
            <td class="mono">{{ formatBytes(row.totalBytes) }}</td>
            <td class="mono">{{ formatBytes(row.downloadBytes) }}</td>
            <td class="mono">{{ formatBytes(row.uploadBytes) }}</td>
            <td><span>{{ formatDate(row.periodStart) }}</span><small>至 {{ formatDate(row.periodEnd) }}</small></td>
            <td class="mono">{{ row.eventCount.toLocaleString('zh-CN') }}</td>
          </tr>
        </tbody>
      </table>
      <div class="pagination"><button class="button button--secondary" :disabled="page <= 1 || loading" @click="previousPage">上一页</button><span>第 {{ page }} 页 · 共 {{ total.toLocaleString('zh-CN') }} 条</span><button class="button button--secondary" :disabled="page * pageSize >= total || loading" @click="nextPage">下一页</button></div>
    </div>
  </section>
</template>

<style scoped>
.usage-filters { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; padding: 15px 16px; border-bottom: 1px solid var(--cb-border); }
.usage-filters label { display: grid; min-width: 0; gap: 6px; color: var(--cb-text); font-size: 11px; font-weight: 650; }
.usage-filters input { width: 100%; min-width: 0; min-height: 35px; border: 1px solid var(--cb-border-strong); border-radius: 5px; padding: 0 9px; background: var(--cb-surface); color: var(--cb-text); font: inherit; font-weight: 400; }
.usage-filters input:focus { border-color: var(--cb-primary); outline: 0; box-shadow: 0 0 0 3px var(--cb-primary-soft); }
.usage-filter-actions { display: flex; align-items: end; gap: 8px; grid-column: 1 / -1; }
@media (max-width: 1050px) { .usage-filters { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
@media (max-width: 560px) { .usage-filters { grid-template-columns: 1fr; padding: 12px 10px; } .usage-filter-actions { align-items: stretch; } .usage-filter-actions > * { flex: 1; } }
</style>
