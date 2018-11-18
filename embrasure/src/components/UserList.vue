<template>
<el-container>
  <el-aside width="200px" style="background-color: #808471">
    <el-menu :default-active="activeIndex" class="el-menu-demo" mode="vertical" background-color="#808471" text-color="#fff" active-text-color="#ffd04b">
    </el-menu>
  </el-aside>
  <el-main>
      <div style="float: right; margin-bottom: 1px">
        <el-row>
          <el-col>
            <el-input v-model="filters[0].value" placeholder="search"></el-input>
          </el-col>
        </el-row>
      </div>
      <data-tables :data="resources" :table-props="tableProps" :page-size="10" :pagination-props="{ background: true, pageSizes: [10, 20, 50, 100] }" :filters="filters" highlight-current-row @row-click="fetchEntity" @selection-change="handleSelectionChange">
       <el-table-column type="selection" width="55"></el-table-column>
       <el-table-column v-for="col in columns" :prop="col.prop" :label="col.label" :key="col.label" sortable="custom" width="200" header-align="center">
       </el-table-column>
      </data-tables>
  </el-main>
  </el-container>
</template>

<script>
/* eslint-disable */
import axios from "axios"

export default {
  name: "UserList",
  data() {
    return {
      resources: [],
      activeIndex: "1",
      multipleSelection: [],
      columns: [{
          prop: "username",
          label: "Username"
          }, {
          prop: "displayname",
          label: "Name"
        }
      ],
     tableProps: {
        border: false,
        stripe: true,
        defaultSort: {
          prop: 'username',
          order: 'ascending'
        }
     },
      filters: [
        {
          prop: ['username', 'displayname'],
          value: ''
        }
      ]
    }
    },
    created() {
    },
    methods: {
      fetchEntity(val) {
        this.$router.push({name: "UserDetails", params: val});
      }
    }
};
</script>