<template :holder="holder" :fieldName="fieldName" :isAdminRole="isAdminRole">
<div>
    <div style="float: left; display: inline-block; width:200px; padding-right: 20px;">
        <select v-model="selectedResIndex" :size="5" style="width: 100%; min-height: 175px;" @change="selectCurRole">
            <option class="el-select-dropdown__item"
                v-for="(r, index) in roles"
                :key="r.modId"
                :label="r.name"
                :value="index" :title="r.name">
                <span class="option_span_item">{{r.name}}</span>
            </option>
        </select>
        <div style="padding: 1px;"/>
        <el-button type="success" round size="mini" @click="openRoleSearch">+</el-button>
        <el-button type="warning" round size="mini" @click="deleteRole">-</el-button>
    </div>
    <TemporalConstraints v-if="curRole != null" :tcHolder="curRole"/>
    <el-dialog title="Select Role" :visible.sync="roleDialogVisible" width="30%" center modal @open="setFocusRoleSelector">
      <el-select ref="roleSelector" v-model="selectedRoles" multiple filterable remote reserve-keyword placeholder="Type first three letters of role" :remote-method="searchRoles" :loading="loading">
        <el-option
          v-for="(r, index) in foundRoles"
          :key="r.modId"
          :label="r.name"
          :value="index" :title="r.name">
        </el-option>
      </el-select>
      <el-button type="success" round size="mini" @click="addSelectedRoles">Ok</el-button>
    </el-dialog>
</div>
</template>

<script>
/* eslint-disable */
import TemporalConstraints from './TemporalConstraints.vue'
import axios from "axios"
import * as ft from "../lib/fortress"

export default {
  name: 'RoleAssignment',
props: {
  holder: Object,
  fieldName: String,
  isAdminRole: Boolean
},
data() {
    return {
        selectedResIndex: 0,
        curRole: null,
        selectedRoles: [],
        roleDialogVisible: false,
        foundRoles: [],
        loading: false
    }
},
beforeUpdate() {
    this.selectCurRole()
},
beforeDestroy() {
    console.log('beforeDestroy')
},
computed: {
    roles: {
        get() {
            this.selectedResIndex = 0
            console.log('computing roles get()')
            let existing = this.holder[this.fieldName]
            if(existing == null) {
                existing = []
            }

            return existing
        },
        set(newVal) {
            console.log('setting new values')
            // ignore
        }
    }
},
methods: {
    selectCurRole() {
        let existing = this.holder[this.fieldName]
        if(existing != null && existing.length > 0) {
            console.log('updating cur role ' + this.selectedResIndex )
            this.curRole = existing[this.selectedResIndex]
        } else {
            console.log('setting cur role to NULL')
            this.curRole = null
        }
    },
    openRoleSearch() {
        this.selectedRoles = []
        this.roleDialogVisible = true
    },
    deleteRole() {
        let existing = this.holder[this.fieldName]
        if(existing != null) {
            existing.splice(this.selectedResIndex, 1)
        }
    },
    updateItem(index) {
        let inputRef = this.fieldName + index
        let newVal = this.$refs[inputRef][0].value
        let existing = this.holder[this.fieldName]
        if(existing != null) {
            existing[index] = newVal
        }        
    },
    roleDialogClose(dropdownOpened) {
        if(!dropdownOpened) {
            this.roleDialogVisible = false
        }
    },
    setFocusRoleSelector() {
        this.$nextTick(function(){
        this.$refs.roleSelector.focus()
        })
    },
    addSelectedRoles() {
        this.roleDialogVisible = false
        console.log(this.selectedRoles)
        let selected = this.selectedRoles
        let existing = this.holder[this.fieldName]
        if(existing == null) {
            this.$set(this.holder, this.fieldName, [])
            existing = this.holder[this.fieldName]
        }
        for(let i=0; i < selected.length; i++) {
            let sr = this.foundRoles[selected[i]]
            let add = true
            for(let j=0; j < existing.length; j++) {
                let er = existing[j]
                if(er.modId == sr.modId) {
                    add = false
                    break
                }
            }
            if(add) {
                let ur = this.convertRoleToUserRole(sr)
                console.log('adding role')
                existing.push(ur)
            }
        }
    },
    convertRoleToUserRole(role) {
        let userRole = {
            fqcn: 'org.apache.directory.fortress.core.model.UserRole'
        }
        if(this.isAdminRole) {
            userRole.fqcn = 'org.apache.directory.fortress.core.model.UserAdminRole'
        }

        userRole.userId = this.holder.userId
        userRole.name = role.name
        userRole.isGroupRole = false
        userRole.timeout = role.timeout
        userRole.beginTime = role.beginTime
        userRole.endTime = role.endTime
        userRole.beginDate = role.beginDate
        userRole.endDate = role.endDate
        userRole.beginLockDate = role.beginLockDate
        userRole.endLockDate = role.endLockDate
        userRole.dayMask = role.dayMask
        userRole.parents = role.parents
        userRole.roleConstraints = null

        return userRole
    },
    searchRoles(query) {
        this.selectedRoles = []
        if (query.length > 2) {
          this.loading = true
          let ftReq = {
                        "value": query,
                        contextId: ft.CONTEXT_ID
                      }
          let url = ft.FT_BASE_URL + '/roleSearch'
          if(this.isAdminRole) {
              url = ft.FT_BASE_URL + '/arleSearch'
          }
          setTimeout(() => {
            axios.post(url, ftReq, ft.AXIOS_FT_CONFIG).then(resp => {
                this.foundRoles = resp.data.entities
                this.loading = false
            }).catch(e => {
                this.foundRoles = []
                ft.showErr(e, '')
            })
          }, 200);
        }
    }
},
components: {
    TemporalConstraints
}
};
</script>
