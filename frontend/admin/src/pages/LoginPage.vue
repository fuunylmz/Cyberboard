<script setup lang="ts">
import { reactive, ref } from 'vue'; import { useRouter } from 'vue-router'; import { useAuthStore } from '../stores/auth'
const form = reactive({ email:'admin@example.com', password:'password' }); const submitting = ref(false); const auth = useAuthStore(); const router = useRouter()
async function submit() { submitting.value=true; await new Promise((resolve) => setTimeout(resolve, 300)); auth.login(form.email); router.push('/admin'); submitting.value=false }
</script>
<template><main class="login-page"><section class="login-panel"><div class="brand brand--login"><span class="brand-mark">C</span><span>Cyberboard</span></div><p class="eyebrow">CONTROL PLANE</p><h1>登录管理后台</h1><p class="login-description">管理用户、订阅、节点和配置发布。</p><form @submit.prevent="submit"><label>邮箱<input v-model="form.email" type="email" autocomplete="username" required /></label><label>密码<input v-model="form.password" type="password" autocomplete="current-password" required /></label><button class="primary-button" type="submit" :disabled="submitting">{{ submitting ? '正在验证…' : '登录' }}</button></form><p class="login-note">当前为前端占位登录，接入 API 后由服务端验证凭据。</p></section></main></template>
