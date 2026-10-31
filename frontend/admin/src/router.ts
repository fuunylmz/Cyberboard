import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from './stores/auth'
import AdminLayout from './layouts/AdminLayout.vue'
import LoginPage from './pages/LoginPage.vue'
import DashboardPage from './pages/DashboardPage.vue'
import NodesPage from './pages/NodesPage.vue'
import UsersPage from './pages/UsersPage.vue'
import SubscriptionsPage from './pages/SubscriptionsPage.vue'
const router = createRouter({ history:createWebHistory(), routes:[
  { path:'/login', component:LoginPage, meta:{ public:true } },
  { path:'/admin', component:AdminLayout, meta:{ requiresAuth:true }, children:[
    { path:'', redirect:'/admin/dashboard' }, { path:'dashboard', name:'总览', component:DashboardPage }, { path:'nodes', name:'节点', component:NodesPage }, { path:'users', name:'用户', component:UsersPage }, { path:'subscriptions', name:'订阅', component:SubscriptionsPage },
  ] }, { path:'/:pathMatch(.*)*', redirect:'/admin' },
] })
router.beforeEach((to) => { const auth = useAuthStore(); if (to.meta.requiresAuth && !auth.isAuthenticated) return '/login'; if (to.path === '/login' && auth.isAuthenticated) return '/admin' })
if (typeof window !== 'undefined') window.addEventListener('cyberboard:unauthorized', () => { const auth = useAuthStore(); auth.logout(); if (router.currentRoute.value.path !== '/login') router.replace('/login') })
export default router
