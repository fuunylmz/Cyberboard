<script setup lang="ts">
const props = defineProps<{ status: string; label?: string }>()
const tone = (status: string) => ['online','active','succeeded','applied'].includes(status) ? 'success' : ['maintenance','pending','running','rolled_back'].includes(status) ? 'warning' : ['error','banned','revoked','expired','failed'].includes(status) ? 'danger' : 'neutral'
</script>
<template><span class="status-badge" :class="`status-badge--${tone(props.status)}`"><span class="status-badge__dot" aria-hidden="true" />{{ label ?? status }}</span></template>
<style scoped>
.status-badge { display:inline-flex; align-items:center; gap:6px; border-radius:999px; padding:4px 9px; font-size:12px; font-weight:650; line-height:1; white-space:nowrap }.status-badge__dot { width:6px; height:6px; border-radius:50%; background:currentColor }.status-badge--success { color:var(--cb-success); background:var(--cb-success-soft) }.status-badge--warning { color:var(--cb-warning); background:var(--cb-warning-soft) }.status-badge--danger { color:var(--cb-danger); background:var(--cb-danger-soft) }.status-badge--neutral { color:var(--cb-text-muted); background:var(--cb-surface-muted) }
</style>
