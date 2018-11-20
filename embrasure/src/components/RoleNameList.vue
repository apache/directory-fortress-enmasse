<template :holder="holder" :fieldName="fieldName" :isAdminRole="isAdminRole">
<div>
    <div style="float: left; display: inline-block; width:261px;">
        <select v-model="selectedResIndex" :size="5" style="width: 100%; min-height: 175px;">
            <option class="el-select-dropdown__item"
                v-for="(r, index) in roles"
                :key="r"
                :label="r"
                :value="index" :title="r">
                <span class="option_span_item">{{index+1}}.&nbsp;{{r}}</span>
            </option>
        </select>
        <div style="padding: 1px;"/>
        <el-button type="success" round size="mini" @click="openRoleSearch">+</el-button>
        <el-button type="warning" round size="mini" @click="deleteRole">-</el-button>
    </div>
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
import axios from "axios"
import * as ft from "../lib/fortress"

export default {
name: 'RoleNameList',
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
        }
    }
},
methods: {
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
                if(er.toLowerCase() == sr.name.toLowerCase()) {
                    add = false
                    break
                }
            }
            if(add) {
                existing.push(sr.name)
            }
        }
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
}
};
</script>
