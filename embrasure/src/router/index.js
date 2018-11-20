/* eslint-disable */
import Vue from 'vue'
import ViewRouter from 'vue-router'
import UserList from '@/components/UserList'
import UserParent from '@/components/UserParent'
import Users from '@/components/Users'
import Roles from '@/components/Roles'
import PermObjects from '@/components/PermObjects'
import Permissions from '@/components/Permissions'

Vue.use(ViewRouter)

export default new ViewRouter({
  routes: [
    {
      path: '/',
      name: 'Users',
      component: Users
    },
    {
      path: '/roles',
      name: 'Roles',
      component: Roles,
    },
    {
      path: '/pobjs',
      name: 'PermObjects',
      component: PermObjects,
    },
    {
      path: '/perms',
      name: 'Permissions',
      component: Permissions,
    }
  ]
})
