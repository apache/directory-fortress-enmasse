<template>
<el-container>
  <el-main>
    <el-row type="flex" justify="start" style="padding-bottom: 4px; text-align: left;">
          <el-col :span="20">
            <el-input style="width: 270px; padding-right: 20px;" v-model="filters[0].value" placeholder="search"></el-input>
              <el-button type="primary" v-if="multipleSelection.length > 0" @click="deleteEntities">Delete</el-button>
              <el-button type="primary" @click="newUser">New User</el-button>
              <el-button type="primary" v-if="enableSave" @click="save">Save</el-button>
          </el-col>
    </el-row>
    <el-row type="flex" justify="start">
      <el-col :span="10" justify="center">
      <data-tables ref="userTable" :data="entities" :table-props="tableProps" :page-size="10" :pagination-props="{ background: true, pageSizes: [10, 20, 50, 100] }" :filters="filters" :highlight-current-row="true" max-height="250" @row-click="showEntity" @selection-change="handleSelectionChange">
        <el-table-column type="selection" width="55"></el-table-column>
        <el-table-column v-for="col in columns" :prop="col.prop" :label="col.label" :key="col.label" sortable="custom" width="200" header-align="center">
        </el-table-column>
      </data-tables>
      </el-col>

      <el-col :span="25">
        <el-form v-if="entity != null" v-model.lazy="entity" :inline="true" label-width="120px">
        <el-tabs v-model="curTab" type="border-card">
          <el-tab-pane name="User Details" label="User Details">
            <el-row justify="start" type="flex">
            <el-col :span="19">
            <el-row justify="start" type="flex">
              <el-form-item label="User ID:">
                <el-input label="User ID" placeholder="User ID" v-model="entity.userId" size="small"></el-input>
              </el-form-item>
              <el-form-item label="Password:">
                <el-input type="password" label="Password" v-model="entity.password" size="small"></el-input>
              </el-form-item>
            </el-row>
            <el-row justify="start" type="flex">
              <el-form-item label="Title:">
                <el-input label="Title" v-model="entity.title" size="small"></el-input>
              </el-form-item>
              <el-form-item label="Display Name:">
                <el-input label="Display Name" v-model="entity.displayName" size="small"></el-input>
              </el-form-item>
            </el-row>
            <el-row justify="start" type="flex">
              <el-form-item label="Organization:">
                <el-input label="Organization" placeholder="Organization" v-model="entity.ou" size="small"></el-input>
              </el-form-item>
              <el-form-item label="Employee Type:">
                <el-input label="Employee Type" v-model="entity.employeeType" size="small"></el-input>
              </el-form-item>
            </el-row>
            <el-row justify="start" type="flex">
              <el-form-item label="Description:">
                <el-input label="Description" v-model="entity.description" size="small"></el-input>
              </el-form-item>
              <el-form-item label="Password Policy:">
                <el-input label="Password Policy" placeholder="" v-model="entity.pwPolicy" size="small"></el-input>
              </el-form-item>
            </el-row>
            <el-row justify="start" type="flex" v-if="entity.internalId != null">
                <el-form-item v-if="!entity.reset" label="New Password:">
                  <el-input type="password" label="New Password:" v-model="entity.newPassword" size="mini"></el-input>
                </el-form-item>
                <el-form-item label="">
                  <el-button type="primary" size="mini" v-if="!entity.reset" @click="resetPassword">Reset Password</el-button>
                  <el-button type="primary" size="mini" @click="lockOrUnlockUser">{{entity.locked? 'Unlock' : 'Lock'}}</el-button>
                </el-form-item>
            </el-row>
            </el-col>
            <el-col :span="4">
                <label class="el-form-item__label" style="width: 33px;">Photo</label>
                <img v-if="entity.jpegPhoto == null" ref="userPhoto" height="125" width="125" src="../assets/nophoto.jpg" @click="selectJpegPhoto"/>
                <img v-else ref="userPhoto" height="125" width="125" :src="jpegPhoto" @click="selectJpegPhoto"/>
                <input type="file" ref="photoFile" @change="changeJpegPhoto" style="opacity: 0; width: 0px; height: 0px">
            </el-col>
            </el-row>
          </el-tab-pane>
          <el-tab-pane name="Role Assignments" label="Role Assignments">
            <!-- <el-form-item label="Roles:" label-width="50px"> -->
              <RoleAssignment :holder.sync="entity" fieldName="roles"/>
            <!-- </el-form-item> -->
          </el-tab-pane>
          <el-tab-pane name="Admin Role Assignments" label="Admin Role Assignments">
            <!-- <el-form-item label="Roles:" label-width="50px"> -->
              <RoleAssignment :holder.sync="entity" fieldName="adminRoles" isAdminRole/>
            <!-- </el-form-item> -->
          </el-tab-pane>
          <el-tab-pane name="Contact Information" label="Contact Information">
            <el-row justify="start" type="flex">
              <ContactInformation :entity="entity"/>
            </el-row>
          </el-tab-pane>
          <el-tab-pane name="Temporal Constraints" label="Temporal Constraints">
            <TemporalConstraints :tcHolder="entity"/>
          </el-tab-pane>
          <el-tab-pane name="System Information" label="System Information">
            <el-row justify="start" type="flex">
              <el-form-item label="System:">
                <el-checkbox v-model="entity.system" size="small"></el-checkbox>
              </el-form-item>
            </el-row>
            <el-row justify="start" type="flex">
              <el-form-item label="Internal ID:">
                <span style="color: black;">{{entity.internalId}}</span>
              </el-form-item>
            </el-row>
            <el-row justify="start" type="flex">
              <el-form-item label="CN:">
                <el-input label="CN" v-model="entity.cn" size="small"></el-input>
              </el-form-item>
            </el-row>
            <el-row justify="start" type="flex">
              <el-form-item label="DN:">
                <span style="color: black;">{{entity.dn}}</span>
              </el-form-item>
            </el-row>
            <el-row justify="start" type="flex">
              <el-form-item label="SN:">
                <el-input label="SN" v-model="entity.sn" size="small"></el-input>
              </el-form-item>
            </el-row>
          </el-tab-pane>
        </el-tabs>
        </el-form>
      </el-col>
    </el-row>
  </el-main>
  </el-container>
</template>

<script>
/* eslint-disable */
import axios from "axios"
import * as ft from "../lib/fortress"
import * as jsondiff from "rfc6902"
import SplitPane from 'vue-split-pane'
import TemporalConstraints from './TemporalConstraints.vue'
import List from './List.vue'
import RoleAssignment from './RoleAssignment.vue'
import ContactInformation from './ContactInformation.vue'
import { Notification } from 'element-ui'

export default {
  name: "Users",
  data() {
    return {
      entities: [],
      entity: null,
      rowIndex: -1,
      curTab: 'User Details',
      multipleSelection: [],
      enableSave: false,
      columns: [{
          prop: "userId",
          label: "User ID"
          }, {
          prop: "name",
          label: "Name"
        }
      ],
     tableProps: {
        border: false,
        stripe: true,
        defaultSort: {
          prop: 'userId',
          order: 'ascending'
        }
     },
      filters: [
        {
          prop: ['userId', 'name', 'displayName'], // roles and adminRoles are handled specially in filterRows function
          value: '',
          filterFn: this.filterRows
        }
      ]
    }
    },
    created() {
      let ftReq = {
                  	entity: {
		                  fqcn: "org.apache.directory.fortress.core.model.User"
	                  },
                    contextId: ft.CONTEXT_ID
                  }
      ft.showWait()
      axios.post(ft.FT_BASE_URL+ '/userSearch', ftReq, ft.AXIOS_FT_CONFIG).then(resp => {
        this.entities = resp.data.entities
        if(this.entities.length > 0) {
          this.showEntity(this.entities[0])
        }
        ft.closeWait()
      }).catch(e => {
        ft.showErr(e, '')
      })
    },
    computed: {
      jpegPhoto: {
        get() {
          return 'data:image/jpeg;base64,' + this.entity.jpegPhoto
        }
      }
    },
    watch: {
      entity: {
        deep: true,
      handler: function(newVal, oldVal) {
          if(this.entity._justLoaded) {
            delete this.entity._justLoaded
          }
          else {
            this.enableSave = true
          }
        }
      }
    },
    methods: {
      newUser() {
        this.entity = ft.newUser()
        this.entity._justLoaded = true
      },
      showEntity(val) {
        if(val !== undefined && val != null) {
          this.enableSave = false
          this.rowIndex = this.entities.indexOf(val)
          // deep clone
          this.entity = JSON.parse(JSON.stringify(val))
          this.entity._justLoaded = true
          //console.log(this.$refs.userTable)
        }
      },
      handleSelectionChange(val) {
        this.multipleSelection = val;
      },
      async save() {
        ft.showWait()
        let newUser = false
        let url = ft.FT_BASE_URL+ '/userUpdate'
        if(this.entity.internalId == null || this.entity.internalId == undefined) {
          url = ft.FT_BASE_URL+ '/userAdd'
          newUser = true
          this.entity.fqcn = 'org.apache.directory.fortress.core.model.User'
        }
        let ftReq = {
                  	entity: this.entity,
                    contextId: ft.CONTEXT_ID
                  }
        axios.post(url, ftReq, ft.AXIOS_FT_CONFIG).then(resp => {
          let rolesTobeAssigned = []
          let rolesTobeDeAssigned = []
          let admRolesTobeAssigned = []
          let admRolesTobeDeAssigned = []
          if(newUser) {
            if(this.entity.roles != null) {
              rolesTobeAssigned = this.entity.roles
            }
            if(this.entity.adminRoles != null) {
              admRolesTobeAssigned = this.entity.adminRoles
            }
          }
          else {
            let origEntity = this.entities[this.rowIndex]
            if(origEntity.roles == null) {
                if(this.entity.roles != null) {
                  rolesTobeAssigned = this.entity.roles
                }
            }
            else {
              let origRoles = origEntity.roles
              let roles = this.entity.roles.slice() // if we don't slice here later the UI is failing to refresh properly
              for(let i=0; i< origRoles.length; i++) {
                 let or = origRoles[i]
                 let found = false
                 let j=0
                for(; j< roles.length; j++) {
                  let r = roles[j]
                  if(or.modId == r.modId) {
                      found = true
                      let op = jsondiff.createPatch(or, r)
                      if(op.length > 0) {
                        rolesTobeAssigned.push(r)
                      }
                      break
                  }
                }
                if(found) {
                  roles.splice(j, 1)
                }
                else {
                  rolesTobeDeAssigned.push(or)
                }
              }
              rolesTobeAssigned.push(...roles) // remaining are the new roles
            }

            if(origEntity.adminRoles == null) {
                if(this.entity.adminRoles != null) {
                  admRolesTobeAssigned = this.entity.adminRoles
                }
            }
            else {
              let origAdmRoles = origEntity.adminRoles
              let admRoles = this.entity.adminRoles.slice() // if we don't slice here later the UI is failing to refresh properly
              for(let i=0; i< origAdmRoles.length; i++) {
                 let or = origAdmRoles[i]
                 let found = false
                 let j=0
                for(; j< admRoles.length; j++) {
                  let r = admRoles[j]
                  if(or.modId == r.modId) {
                      found = true
                      let op = jsondiff.createPatch(or, r)
                      if(op.length > 0) {
                        admRolesTobeAssigned.push(r)
                      }
                      break
                  }
                }
                if(found) {
                  admRoles.splice(j, 1)
                }
                else {
                  admRolesTobeDeAssigned.push(or)
                }
              }
              admRolesTobeAssigned.push(...admRoles) // remaining are the new roles
            }
          }
          try {
            this.updateRoleAssignments(rolesTobeDeAssigned, ft.FT_BASE_URL + '/roleDeasgn')
            this.updateRoleAssignments(rolesTobeAssigned, ft.FT_BASE_URL + '/roleAsgn')
            this.updateRoleAssignments(admRolesTobeDeAssigned, ft.FT_BASE_URL + '/arleDeasgn')
            this.updateRoleAssignments(admRolesTobeAssigned, ft.FT_BASE_URL + '/arleAsgn')
            let readPromise = this.fetchSingleUser(this.entity.userId)
            readPromise.then( resp => {
              console.log('fetching user')
              if(newUser) {
                this.entities.push(resp.data.entity)
                this.showEntity(resp.data.entity)
              }
              else {
                let origEntity = this.entities[this.rowIndex]
                // Object.assign(origEntity, resp.data.entity)
                origEntity = {...origEntity, ...resp.data.entity}
                this.$set(this.entities, this.rowIndex, origEntity)
              }
              this.enableSave = false
              ft.closeWait()
            })
          }
          catch(e) {
            ft.showErr(e, '')
          }
        }).catch(e => {
          console.log(e)
          ft.showErr(e, '')
        })
      },
      changeJpegPhoto() {
        let f = this.$refs.photoFile.files[0]
        console.log(f.type)
        if(!f.type.startsWith('image/jpeg')) {
          ft.showErr('Invalid image')
          return
        }
        if(f.size > 1048576) { // 1 MB
          ft.showErr('Photo size cannot exceed 1MB, please select an image with smaller size')
          return
        }
        let fileReader = new FileReader()
        let imgRef = this.$refs.userPhoto
        let self = this
        fileReader.addEventListener('load', function(){
          let img = fileReader.result
          let commaPos = img.indexOf(',')
          img = img.substring(commaPos+1)
          console.log(img)
          self.$set(self.entity, 'jpegPhoto', img)
        }, false)
        fileReader.readAsDataURL(f)
      },
      selectJpegPhoto() {
        this.$refs.photoFile.click()
      },
      async updateRoleAssignments(roles, url) {
        console.log('updating role assignment')
        for(let i=0; i< roles.length; i++) {
          let ftReq = {
                      entity: roles[i],
                      contextId: ft.CONTEXT_ID
                    }
          let respPromise = await axios.post(url, ftReq, ft.AXIOS_FT_CONFIG)
        }
      },
      async fetchSingleUser(userId) {
          let ftReq = {
                      entity: {
                        fqcn: 'org.apache.directory.fortress.core.model.User',
                        userId: userId
                      },
                      contextId: ft.CONTEXT_ID
                    }
        let respPromise = await axios.post(ft.FT_BASE_URL + '/userRead', ftReq, ft.AXIOS_FT_CONFIG)
        console.log(respPromise)
        return respPromise
      },
      lockOrUnlockUser() {
        let ftReq = {
                      entity: {
                        fqcn: 'org.apache.directory.fortress.core.model.User',
                        userId: this.entity.userId
                      },
                      contextId: ft.CONTEXT_ID
                    }
        ft.showWait()
        let origEntity = this.entities[this.rowIndex]
        let url = ft.FT_BASE_URL+ '/userLock'
        if(origEntity.locked) {
          url = ft.FT_BASE_URL+ '/userUnlock'
        }
        let saveState = this.enableSave
        axios.post(url, ftReq, ft.AXIOS_FT_CONFIG).then(resp => {
          origEntity.locked = !origEntity.locked
          this.entity.locked = origEntity.locked
          if(!saveState) {
            this.entity._justLoaded = true
          }
          ft.closeWait()
        }).catch(e => {
          ft.showErr(e, '')
        })
      },
      resetPassword() {
        if(this.entity.newPassword == null || this.entity.newPassword.trim().length == 0) {
          ft.showErr('New password cannot be empty')
          return
        }
        let ftReq = {
                      entity: this.entity,
                      contextId: ft.CONTEXT_ID
                    }
        ft.showWait()
        let saveState = this.enableSave
        axios.post(ft.FT_BASE_URL+ '/userReset', ftReq, ft.AXIOS_FT_CONFIG).then(resp => {
          this.entity.reset = true
          this.entities[this.rowIndex].reset = true
          if(!saveState) {
            this.entity._justLoaded = true
          }
          ft.closeWait()
        }).catch(e => {
          ft.showErr(e, '')
        })
      },
      deleteEntities() {
        ft.showWait()
        for(let i=0; i< this.multipleSelection.length; i++) {
          let e = this.multipleSelection[i]
          let respPromise = this._deleteSingleEntity(e)
          respPromise.then(resp => {
            let row = this.entities.indexOf(e)
            this.entities.splice(row, 1)
          }).catch(e => {
            let msg = 'Failed to delete user ' + e.userId
            Notification.warning({message: msg, duration: 10000})
          })
        }

        if(this.entities.length > 0) {
          this.showEntity(this.entities[0])
        }
        ft.closeWait()
      },
      async _deleteSingleEntity(e) {
          let ftReq = {
                        entity: e,
                        contextId: ft.CONTEXT_ID
                      }
          let respPromise = await axios.post(ft.FT_BASE_URL+ '/userDelete', ftReq, ft.AXIOS_FT_CONFIG)
          return respPromise
      },
      filterRows(row, filter) {
        let show = false
        for(let i=0; i < filter.prop.length; i++){
          let name = filter.prop[i]
          let val = row[name]
          if(val !== null && val !== undefined) {
            val = (''+val).toLowerCase()
            if(val.indexOf(filter.value) != -1) {
              show = true
              break
            }
          }
        }
        if(!show) {
          if(this.searchRoleNames(filter.value, row.roles)) {
            show = true
          }
          else {
            show = this.searchRoleNames(filter.value, row.adminRoles)
          }
        }
        return show
      },
      searchRoleNames(val, roles) {
        if(roles == null || roles == undefined) {
          return false
        }
        for(let i=0; i < roles.length; i++) {
          let rname = roles[i].name.toLowerCase()
          if(rname.indexOf(val) != -1) {
            return true
          }
        }
        return false
      }
    },
    components: {
      SplitPane,
      TemporalConstraints,
      List,
      RoleAssignment,
      ContactInformation
    }
};
</script>
