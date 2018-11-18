<template>
  <div id="app">
    <div>
      <el-container style="border: 1px solid #eee">
        <el-header style="text-align: right; font-size: 12px; padding: 0px;">
            <el-menu router :default-active="activeIndex" class="el-menu-demo" mode="horizontal" background-color="#545c64" text-color="#fff" active-text-color="#ffd04b">
              <el-menu-item index="/" >Users</el-menu-item>
              <el-menu-item index="/groups">Groups</el-menu-item>
              <el-submenu index="rbac">
                <template slot="title">RBAC</template>
                <el-menu-item index="/roles">Roles</el-menu-item>
                <el-menu-item index="/perms">Perms</el-menu-item>
                <el-menu-item index="/ssds">SSDs</el-menu-item>
                <el-menu-item index="/dsds">DSDs</el-menu-item>
              </el-submenu>
              <el-submenu index="arbac">
                <template slot="title">ARBAC</template>
                <el-menu-item index="/policies">Policies</el-menu-item>
              </el-submenu>
              <el-menu-item index="/pobjs">PObjs</el-menu-item>
              <el-menu-item index="/ousers">OUsers</el-menu-item>
              <el-menu-item index="/ouprms">OUPrms</el-menu-item>
              <el-menu-item index="/admrles">ADMRLEs</el-menu-item>
              <el-menu-item index="/admobjs">ADMObjs</el-menu-item>
              <el-menu-item index="/admperms">ADMPerms</el-menu-item>
              <el-menu-item index="/logout">Logout</el-menu-item>
            </el-menu>
          </el-header>
      </el-container>
    </div>
    <div>
        <router-view/>
    </div>
  </div>
</template>

<script>
import axios from "axios"

export default {
  name: 'app',
  data() {
    return {
      activeIndex: '/'
    }
  }
}
</script>

<style>
#app {
  font-family: 'Avenir', Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-align: center;
  color: #2200cc;
}
.split-pane {
  display: flex;
  flex-direction: row;
  height: 80%;
}

.split-pane-item,
.split-pane-gutter {
  height: 80%;
}

.split-pane-gutter {
  background: #000;
  opacity: 0.2;
  z-index: 1;
  box-sizing: border-box;
  background-clip: padding-box;
  width: 11px;
  margin: 0 -5px;
  border-left: 5px solid rgba(255, 255, 255, 0);
  border-right: 5px solid rgba(255, 255, 255, 0);
  cursor: col-resize;
}

.split-pane-gutter:hover,
.split-pane-gutter:focus {
  border-left: 5px solid rgba(0, 0, 0, 0.5);
  border-right: 5px solid rgba(0, 0, 0, 0.5);
  transition: all 2s ease;
}

.is-dragging {
  cursor: col-resize;
}
</style>