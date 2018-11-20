<template>
<el-container>
  <el-main>
    <el-row type="flex" justify="start" style="padding-bottom: 4px; text-align: left;">
      <el-col :span="20">
        <el-input style="width: 270px; padding-right: 20px;" v-model="filters[0].value" placeholder="search"></el-input>
          <el-button type="primary" v-if="multipleSelection.length > 0" @click="deleteEntities">Delete</el-button>
          <el-button type="primary" @click="newPermission">New Permission</el-button>
          <el-button type="primary" v-if="enableSave" @click="save">Save</el-button>
      </el-col>
    </el-row>
    <el-row type="flex" justify="start">
      <el-col :span="15" justify="center">
      <data-tables ref="entityTable" :data="entities" :table-props="tableProps" :page-size="10" :pagination-props="{ background: true, pageSizes: [10, 20, 50, 100] }" :filters="filters" :highlight-current-row="true" max-height="200" @row-click="showEntity" @selection-change="handleSelectionChange">
        <el-table-column type="selection" width="55"></el-table-column>
        <el-table-column v-for="col in columns" :prop="col.prop" :label="col.label" :key="col.label" sortable="custom" width="180" header-align="center">
        </el-table-column>
      </data-tables>
      </el-col>

      <el-col :span="15">
        <el-form v-if="entity != null" v-model.lazy="entity" :inline="true" label-width="140px">
        <el-tabs v-model="curTab" type="border-card" style="width: 620px; height: 590px">
          <el-tab-pane name="RBAC Permission Operation Details" label="RBAC Permission Operation Details">
            <el-row justify="start" type="flex">
              <el-form-item label="Object Name:">
                <el-input label="Object Name" v-model="entity.objName" disabled size="small"></el-input>
              </el-form-item>
              <el-col :span="1" style="padding-top: 5px;">
                <el-button type="success" round size="mini" @click="showObjDialog=true">Select Object</el-button>
              </el-col>
            </el-row>
            <el-row justify="start" type="flex">
              <el-form-item label="Operation Name:">
                <el-input ref="firstField" label="Operation Name" placeholder="Operation Name" v-model="entity.opName" size="small"></el-input>
              </el-form-item>
            </el-row>
            <el-row justify="start" type="flex">
              <el-form-item label="Object ID:">
                <el-input label="Operation Name" placeholder="Object ID" v-model="entity.objId" size="small"></el-input>
              </el-form-item>
            </el-row>
            <el-row justify="start" type="flex">
              <el-form-item label="Description:">
                <el-input label="Description" placeholder="Description" v-model="entity.description" size="small"></el-input>
              </el-form-item>
            </el-row>
            <el-row justify="start" type="flex">
              <el-form-item label="internalId:">
                <span style="color: black;">{{entity.internalId}}</span>
              </el-form-item>
            </el-row>
            <el-row justify="start" type="flex">
              <el-form-item label="Roles:">
                <RoleNameList :holder.sync="entity" fieldName="roles"/>
              </el-form-item>
            </el-row>
          </el-tab-pane>
        </el-tabs>
        </el-form>
      </el-col>
    </el-row>
    <el-dialog title="Select Organization" :visible.sync="showObjDialog" width="30%" center modal @open="setFocusOrgSelector">
      <el-select ref="orgSelector" v-model="selectedObj" filterable remote reserve-keyword placeholder="Type first three letters of Organization" :remote-method="searchOrgs" :loading="loading">
        <el-option
          v-for="(r, index) in foundObjs"
          :key="r.internalId"
          :label="r.objName"
          :value="index" :title="r.description">
        </el-option>
      </el-select>
      <el-button type="success" round size="mini" @click="addselectedObj">Ok</el-button>
    </el-dialog>
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
import RoleNameList from './RoleNameList.vue'
import { Notification } from 'element-ui'

export default {
  name: "Permissions",
  data() {
    return {
      entities: [],
      entity: null,
      rowIndex: -1,
      curTab: 'RBAC Permission Operation Details',
      multipleSelection: [],
      enableSave: false,
      showObjDialog: false,
      loading: false,
      selectedObj: null,
      foundObjs: [],
      columns: [{
          prop: "objName",
          label: "Object Name",
          }, {
          prop: "objId",
          label: "Object ID",
          }, {
          prop: "opName",
          label: "Operation Name",
          }, {
          prop: "description",
          label: "Description",
        }
      ],
     tableProps: {
        border: false,
        stripe: true
     },
      filters: [
        {
          prop: ['objName', 'opName', 'description'],
          value: ''
        }
      ]
    }
    },
    created() {
      let ftReq = {
                    entity: {
                      fqcn: 'org.apache.directory.fortress.core.model.Permission',
                      objName: '',
                      opName: ''
                    },
                    contextId: ft.CONTEXT_ID
                  }
      ft.showWait()
      axios.post(ft.FT_BASE_URL+ '/permSearch', ftReq, ft.AXIOS_FT_CONFIG).then(resp => {
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
      newPermission() {
        this.entity = ft.newPermission()
        this.entity._justLoaded = true
        ft.focusFirstField(this)
      },
      showEntity(val) {
        if(val !== undefined && val != null) {
          this.enableSave = false
          this.rowIndex = this.entities.indexOf(val)
          // deep clone
          this.entity = JSON.parse(JSON.stringify(val))
          this.entity._justLoaded = true
        }
      },
      handleSelectionChange(val) {
        this.multipleSelection = val;
      },
      save() {
        ft.showWait()
        let newRole = false
        let url = ft.FT_BASE_URL+ '/permUpdate'
        if(this.entity.internalId == null || this.entity.internalId == undefined) {
          url = ft.FT_BASE_URL+ '/permAdd'
          newRole = true
          this.entity.fqcn = 'org.apache.directory.fortress.core.model.Permission'
        }
        if(this.entity.props == null) {
            this.entity.props = {
                    fqcn: 'org.apache.directory.fortress.core.model.Props'
                  }
        }
        let ftReq = {
                  	entity: this.entity,
                    contextId: ft.CONTEXT_ID
                  }
        axios.post(url, ftReq, ft.AXIOS_FT_CONFIG).then(resp => {
          if(newRole) {
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
        }).catch(e => {
          console.log(e)
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
            let msg = 'Failed to delete permission ' + e.userId
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
          let respPromise = await axios.post(ft.FT_BASE_URL+ '/permDelete', ftReq, ft.AXIOS_FT_CONFIG)
          return respPromise
      },
      setFocusOrgSelector() {
          this.$nextTick(function(){
          this.$refs.orgSelector.focus()
          })
      },
      searchOrgs(query) {
        this.selectedObj = null
        if (query.length > 0) {
          this.loading = true
          let ftReq = {
                        entity: {
                          fqcn: 'org.apache.directory.fortress.core.model.PermObj',
                          objName: query
                        },
                        contextId: ft.CONTEXT_ID
                      }
          let url = ft.FT_BASE_URL + '/objSearch'
          setTimeout(() => {
            axios.post(url, ftReq, ft.AXIOS_FT_CONFIG).then(resp => {
                this.foundObjs = resp.data.entities
                this.loading = false
            }).catch(e => {
                this.foundObjs = []
                ft.showErr(e, '')
            })
          }, 200);
        }
      },
      addselectedObj() {
        console.log(this.selectedObj)
        if(this.selectedObj >= 0) {
          this.entity.objName = this.foundObjs[this.selectedObj].objName
          this.showObjDialog = false
        }
      }
    },
    components: {
      SplitPane,
      TemporalConstraints,
      RoleNameList
    }
};
</script>
