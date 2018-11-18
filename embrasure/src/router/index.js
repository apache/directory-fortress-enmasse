/* eslint-disable */
import Vue from 'vue'
import ViewRouter from 'vue-router'
import UserList from '@/components/UserList'
import UserParent from '@/components/UserParent'
import Users from '@/components/Users'
//import UserDetails from '@/components/UserDetails'

Vue.use(ViewRouter)

export default new ViewRouter({
  routes: [
    {
      path: '/',
      name: 'Users',
      component: Users
    },
    {
      path: '/users',
      component: UserParent,
      children: [
        {
          path: '',
          name: 'UserList',
          component: UserList
        },
        // {
        //   path: ':id',
        //   name: 'UserDetails',
        //   component: UserDetails
        // }
      ]
    }
  ]
})
