import Vue from 'vue'
import VueRouter from 'vue-router'

import Passwords from '../views/Passwords.vue'

Vue.use(VueRouter);

const User = {
  template: '<div>User</div>'
}

const router = new VueRouter({
  routes: [
    {
      path: '/',
      name: 'passwords',
      component: Passwords
    },
    {
      path: '/user',
      name: 'user',
      component: User
    }
  ],
  mode: "history"
})

export default router
