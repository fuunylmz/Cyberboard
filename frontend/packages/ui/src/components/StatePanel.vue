<script setup lang="ts">
defineProps<{ title: string; description?: string; actionLabel?: string }>()
const emit = defineEmits<{ action: [] }>()
</script>
<template><div class="state-panel" role="status"><strong>{{ title }}</strong><p v-if="description">{{ description }}</p><button v-if="actionLabel" type="button" class="button" @click="emit('action')">{{ actionLabel }}</button></div></template>
<style scoped>
.state-panel { padding:42px 24px; border:1px dashed var(--cb-border); border-radius:var(--cb-radius); background:var(--cb-surface-muted); text-align:center; color:var(--cb-text-muted) }.state-panel strong { display:block; color:var(--cb-text); font-size:15px }.state-panel p { margin:8px 0 16px; font-size:13px }.button { border:1px solid var(--cb-border); border-radius:6px; padding:8px 12px; background:var(--cb-surface); color:var(--cb-text); cursor:pointer }
</style>
