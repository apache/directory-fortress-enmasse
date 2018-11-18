import Vue from 'vue'
import App from './App.vue'
import router from './router'
import ElementUI from 'element-ui'
import 'element-ui/lib/theme-chalk/index.css'
import locale from 'element-ui/lib/locale/lang/en'
//import { Notification } from 'element-ui';
import {DataTables} from 'vue-data-tables'

Vue.config.productionTip = false
Vue.use(ElementUI, { locale })
Vue.use(DataTables)

new Vue({
  el: '#app',
  router,
  render: h => h(App),
  components: { App },
  template: '<App/>',
  created: function() {
  }
})