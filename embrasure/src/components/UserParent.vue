<template>
<el-container>
  <el-aside width="200px" style="background-color: #808471">
    <el-menu class="el-menu-demo" mode="vertical" background-color="#808471" text-color="#fff" active-text-color="#ffd04b">
      <el-menu-item index="1" @click="save" v-if="enableSave">Save</el-menu-item>
      <el-menu-item index="2" @click="back">&lt;- User List</el-menu-item>
      <el-menu-item index="3" @click="addEntity">Add New</el-menu-item>
      <!-- <el-menu-item index="4" @click="deleteEntity" v-if="multipleSelection.length > 0">Delete</el-menu-item> -->
    </el-menu>
  </el-aside>
  <router-view class="child"></router-view>
</el-container>
</template>
<script>
/* eslint-disable */
import axios from "axios"

export default {
  name: 'UserParent',
  data() {
    return {
      enableSave: false
    }
  },
  methods: {
    addEntity() {

    },
    deleteEntity() {

    },
    back() {
      
    }
  }
};
</script>
