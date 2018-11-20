<template>
<el-container>
  <el-main>
    <el-row type="flex" justify="start" style="padding-bottom: 4px; text-align: left;">
      <el-col :span="20">
        <el-input style="width: 270px; padding-right: 20px;" v-model="filters[0].value" placeholder="search"></el-input>
          <el-button type="primary" v-if="multipleSelection.length > 0" @click="deleteEntities">Delete</el-button>
          <el-button type="primary" @click="newPermObject">New Object</el-button>
          <el-button type="primary" v-if="enableSave" @click="save">Save</el-button>
      </el-col>
    </el-row>
    <el-row type="flex" justify="start">
      <el-col :span="12" justify="center">
      <data-tables ref="entityTable" :data="entities" :table-props="tableProps" :page-size="10" :pagination-props="{ background: true, pageSizes: [10, 20, 50, 100] }" :filters="filters" :highlight-current-row="true" max-height="200" @row-click="showEntity" @selection-change="handleSelectionChange">
        <el-table-column type="selection" width="55"></el-table-column>
        <el-table-column v-for="col in columns" :prop="col.prop" :label="col.label" :key="col.label" sortable="custom" :width="col.width" header-align="center">
        </el-table-column>
      </data-tables>
      </el-col>

      <el-col :span="20">
        <el-form v-if="entity != null" v-model.lazy="entity" :inline="true" label-width="120px">
        <el-tabs v-model="curTab" type="border-card" style="width: 700px; height: 400px">
          <el-tab-pane name="RBAC Permission Object Details" label="RBAC Permission Object Details">
            <el-row justify="start" type="flex">
              <el-form-item label="Object Name:">
                <el-input ref="firstField" label="Object Name" placeholder="Object Name" v-model="entity.objName" size="small"></el-input>
              </el-form-item>
            </el-row>
            <el-row justify="start" type="flex">
              <el-form-item label="Description:">
                <el-input label="Description" v-model="entity.description" size="small"></el-input>
              </el-form-item>
            </el-row>
            <el-row justify="start" type="flex">
              <el-form-item label="Organization:">
                <el-input label="Organization" v-model="entity.ou" disabled size="small"></el-input>
              </el-form-item>
              <el-col :span="1" style="padding-top: 5px;">
                <el-button type="success" round size="mini" @click="showOrgDialog=true">Select Org</el-button>
              </el-col>
            </el-row>
            <el-row justify="start" type="flex">
              <el-form-item label="Type:">
                <el-input label="Type" v-model="entity.type" size="small"></el-input>
              </el-form-item>
            </el-row>
            <el-row justify="start" type="flex">
              <el-form-item label="internalId:">
                <span style="color: black;">{{entity.internalId}}</span>
              </el-form-item>
            </el-row>
          </el-tab-pane>
        </el-tabs>
        </el-form>
      </el-col>
    </el-row>
    <el-dialog title="Select Organization" :visible.sync="showOrgDialog" width="30%" center modal @open="setFocusOrgSelector">
      <el-select ref="orgSelector" v-model="selectedOrg" filterable remote reserve-keyword placeholder="Type first three letters of Organization" :remote-method="searchOrgs" :loading="loading">
        <el-option
          v-for="(r, index) in foundOrgs"
          :key="r.id"
          :label="r.name"
          :value="index" :title="r.description">
        </el-option>
      </el-select>
      <el-button type="success" round size="mini" @click="addSelectedOrg">Ok</el-button>
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
  name: "PermObjects",
  data() {
    return {
      entities: [],
      entity: null,
      rowIndex: -1,
      curTab: 'RBAC Permission Object Details',
      multipleSelection: [],
      enableSave: false,
      showOrgDialog: false,
      loading: false,
      selectedOrg: null,
      foundOrgs: [],
      columns: [{
          prop: "objName",
          label: "Object Name",
          width: "200"
          }, {
          prop: "ou",
          label: "Organization",
          width: "200"
          }, {
          prop: "descriptiouon",
          label: "Description",
          width: "200"
        }
      ],
     tableProps: {
        border: false,
        stripe: true
     },
      filters: [
        {
          prop: ['objName', 'ou', 'description'],
          value: ''
        }
      ]
    }
    },
    created() {
      let ftReq = {
                    entity: {
                      fqcn: 'org.apache.directory.fortress.core.model.PermObj',
                      objName: ''
                    },
                    contextId: ft.CONTEXT_ID
                  }
      ft.showWait()
      axios.post(ft.FT_BASE_URL+ '/objSearch', ftReq, ft.AXIOS_FT_CONFIG).then(resp => {
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
      newPermObject() {
        this.entity = ft.newPermObject()
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
        let url = ft.FT_BASE_URL+ '/objUpdate'
        if(this.entity.internalId == null || this.entity.internalId == undefined) {
          url = ft.FT_BASE_URL+ '/objAdd'
          newRole = true
          this.entity.fqcn = 'org.apache.directory.fortress.core.model.PermObj'
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
            let msg = 'Failed to delete role ' + e.userId
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
          let respPromise = await axios.post(ft.FT_BASE_URL+ '/objDelete', ftReq, ft.AXIOS_FT_CONFIG)
          return respPromise
      },
      setFocusOrgSelector() {
          this.$nextTick(function(){
          this.$refs.orgSelector.focus()
          })
      },
      searchOrgs(query) {
        this.selectedOrg = null
        if (query.length > 0) {
          this.loading = true
          let ftReq = {
                        entity: {
                          fqcn: 'org.apache.directory.fortress.core.model.OrgUnit',
                          type: 'PERM',
                          name: query
                        },
                        contextId: ft.CONTEXT_ID
                      }
          let url = ft.FT_BASE_URL + '/orgSearch'
          setTimeout(() => {
            axios.post(url, ftReq, ft.AXIOS_FT_CONFIG).then(resp => {
                this.foundOrgs = resp.data.entities
                this.loading = false
            }).catch(e => {
                this.foundOrgs = []
                ft.showErr(e, '')
            })
          }, 200);
        }
      },
      addSelectedOrg() {
        console.log(this.selectedOrg)
        if(this.selectedOrg >= 0) {
          this.entity.ou = this.foundOrgs[this.selectedOrg].name
          this.showOrgDialog = false
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
