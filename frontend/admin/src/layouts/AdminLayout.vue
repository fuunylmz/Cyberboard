<script setup lang="ts">
import { RouterLink, RouterView, useRouter } from 'vue-router'
import { useAuthStore } from '../stores/auth'
const auth = useAuthStore(); const router = useRouter()
const links = [{ to:'/admin/dashboard', label:'总览', icon:'⌂' }, { to:'/admin/nodes', label:'节点', icon:'◈' }, { to:'/admin/users', label:'用户', icon:'◎' }, { to:'/admin/plans', label:'套餐', icon:'◇' }, { to:'/admin/subscriptions', label:'订阅', icon:'▣' }, { to:'/admin/orders', label:'订单', icon:'¥' }, { to:'/admin/config', label:'配置发布', icon:'◆' }, { to:'/admin/audit-logs', label:'审计日志', icon:'◌' }]
function logout() { auth.logout(); router.push('/login') }
</script>
<template>
  <div class="admin-shell"><aside class="sidebar"><div class="brand"><span class="brand-mark">C</span><span>Cyberboard</span></div><div class="sidebar-caption">控制面板</div><nav class="nav-list" aria-label="主导航"><RouterLink v-for="link in links" :key="link.to" :to="link.to" class="nav-link"><span>{{ link.icon }}</span>{{ link.label }}</RouterLink></nav><div class="sidebar-footer">节点与订阅控制台</div></aside><main class="main-content"><header class="topbar"><div><span class="breadcrumb">管理后台</span><span class="breadcrumb-separator">/</span><span class="breadcrumb-current">{{ $route.name ?? '总览' }}</span></div><div class="topbar-actions"><span class="user-name">{{ auth.session?.displayName }}</span><button class="button button--secondary logout-button" type="button" @click="logout">退出</button></div></header><div class="page-content"><RouterView /></div></main></div>
</template>
