import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from './stores/auth'
import AdminLayout from './layouts/AdminLayout.vue'
import LoginPage from './pages/LoginPage.vue'
import DashboardPage from './pages/DashboardPage.vue'
import NodesPage from './pages/NodesPage.vue'
import UsersPage from './pages/UsersPage.vue'
import SubscriptionsPage from './pages/SubscriptionsPage.vue'
import PlansPage from './pages/PlansPage.vue'
import ConfigPage from './pages/ConfigPage.vue'
import OrdersPage from './pages/OrdersPage.vue'
import AuditLogsPage from './pages/AuditLogsPage.vue'
import UsagePage from './pages/UsagePage.vue'
const router = createRouter({ history:createWebHistory(), routes:[
  { path:'/login', component:LoginPage, meta:{ public:true } },
  { path:'/admin', component:AdminLayout, meta:{ requiresAuth:true }, children:[
    { path:'', redirect:'/admin/dashboard' }, { path:'dashboard', name:'总览', component:DashboardPage }, { path:'nodes', name:'节点', component:NodesPage }, { path:'users', name:'用户', component:UsersPage }, { path:'usage', name:'用量', component:UsagePage }, { path:'plans', name:'套餐', component:PlansPage }, { path:'subscriptions', name:'订阅', component:SubscriptionsPage }, { path:'orders', name:'订单', component:OrdersPage }, { path:'config', name:'配置发布', component:ConfigPage }, { path:'audit-logs', name:'审计日志', component:AuditLogsPage },
  ] }, { path:'/:pathMatch(.*)*', redirect:'/admin' },
] })
router.beforeEach((to) => { const auth = useAuthStore(); if (to.meta.requiresAuth && !auth.isAuthenticated) return auth.sessionExpired ? { path: '/login', query: { reason: 'session-expired' } } : '/login'; if (to.path === '/login' && auth.isAuthenticated) return '/admin' })
if (typeof window !== 'undefined') window.addEventListener('cyberboard:unauthorized', () => { const auth = useAuthStore(); auth.logout(); if (router.currentRoute.value.path !== '/login') router.replace({ path: '/login', query: { reason: 'session-expired' } }) })
export default router
