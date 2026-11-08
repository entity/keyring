import { defineAsyncComponent } from 'vue'

/**
 * One component per factor, shared by the challenge and confirm pages.
 * Adding a factor on the server? Add a line here.
 */
export default {
  'password': defineAsyncComponent(() => import('./factors/Password.vue')),
  'totp': defineAsyncComponent(() => import('./factors/Code.vue')),
  'email-code': defineAsyncComponent(() => import('./factors/Code.vue')),
  'recovery': defineAsyncComponent(() => import('./factors/Code.vue')),
  'passkey': defineAsyncComponent(() => import('./factors/SecurityKey.vue')),
  'security-key': defineAsyncComponent(() => import('./factors/SecurityKey.vue')),
}
