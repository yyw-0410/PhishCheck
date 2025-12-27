import { createRouter, createWebHistory } from 'vue-router'

// Lazy load all views for faster initial page load (LCP optimization)
const AnalysisView = () => import('../views/AnalysisView.vue')
const LoginView = () => import('@/views/LoginView.vue')
const SignupView = () => import('@/views/SignupView.vue')
const LinkAnalysisView = () => import('@/views/LinkAnalysisView.vue')
const FileAnalysisView = () => import('@/views/FileAnalysisView.vue')
const OAuthCallback = () => import('@/views/OAuthCallback.vue')
const TermsOfServiceView = () => import('@/views/TermsOfServiceView.vue')
const PrivacyPolicyView = () => import('@/views/PrivacyPolicyView.vue')
const SupportView = () => import('@/views/SupportView.vue')
const FeedbackView = () => import('@/views/FeedbackView.vue')
const AccountView = () => import('@/views/AccountView.vue')
const BillingView = () => import('@/views/BillingView.vue')
const NotificationsView = () => import('@/views/NotificationsView.vue')

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/',
      name: 'home',
      component: AnalysisView,
    },
    {
      path: '/login',
      name: 'login',
      component: LoginView,
      meta: { layout: 'full', guestOnly: true },
    },
    {
      path: '/signup',
      name: 'signup',
      component: SignupView,
      meta: { layout: 'full', guestOnly: true },
    },
    {
      path: '/analyzer/eml',
      name: 'eml-analysis',
      component: AnalysisView,
    },
    {
      path: '/analyzer',
      redirect: '/analyzer/eml',
    },
    {
      path: '/analyzer/link',
      name: 'link-analysis',
      component: LinkAnalysisView,
    },
    {
      path: '/analyzer/file',
      name: 'file-analysis',
      component: FileAnalysisView,
    },
    {
      path: '/auth/microsoft/callback',
      name: 'microsoft-callback',
      component: OAuthCallback,
      meta: { layout: 'full' },
    },
    {
      path: '/auth/google/callback',
      name: 'google-callback',
      component: OAuthCallback,
      meta: { layout: 'full' },
    },
    {
      path: '/terms',
      name: 'terms-of-service',
      component: TermsOfServiceView,
      meta: { layout: 'full' },
    },
    {
      path: '/privacy',
      name: 'privacy-policy',
      component: PrivacyPolicyView,
      meta: { layout: 'full' },
    },
    {
      path: '/support',
      name: 'support',
      component: SupportView,
      meta: { layout: 'full' },
    },
    {
      path: '/feedback',
      name: 'feedback',
      component: FeedbackView,
      meta: { layout: 'full' },
    },
    {
      path: '/account',
      name: 'account',
      component: AccountView,
      meta: { layout: 'full', requiresAuth: true },
    },
    {
      path: '/billing',
      name: 'billing',
      component: BillingView,
      meta: { layout: 'full', requiresAuth: true },
    },
    {
      path: '/notifications',
      name: 'notifications',
      component: NotificationsView,
      meta: { layout: 'full', requiresAuth: true },
    },
    {
      path: '/verify-email',
      name: 'verify-email',
      component: () => import('@/views/EmailVerificationView.vue'),
      meta: { layout: 'full' },
    },
    {
      path: '/:pathMatch(.*)*',
      name: 'not-found',
      component: () => import('../views/NotFound.vue'),
      meta: { layout: 'full' },
    },
  ],
})

// Navigation guard
router.beforeEach((to, _from, next) => {
  const hasUser = !!localStorage.getItem('user')

  // If route requires auth and user is not logged in
  if (to.meta.requiresAuth && !hasUser) {
    next({ name: 'login' })
  }
  // If route is for guests only (login/signup) and user has a session
  else if (to.meta.guestOnly && hasUser) {
    next({ name: 'home' })
  } else {
    next()
  }
})

export default router
