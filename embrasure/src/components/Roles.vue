<template>
<el-container>
  <el-main>
    <el-row type="flex" justify="start" style="padding-bottom: 4px; text-align: left;">
      <el-col :span="20">
        <el-input style="width: 270px; padding-right: 20px;" v-model="filters[0].value" placeholder="search"></el-input>
          <el-button type="primary" v-if="multipleSelection.length > 0" @click="deleteEntities">Delete</el-button>
          <el-button type="primary" @click="newRole">New Role</el-button>
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
        <el-tabs v-model="curTab" type="border-card" style="width: 750px; height: 500px">
          <el-tab-pane name="RBAC Role Details" label="RBAC Role Details">
            <el-row justify="start" type="flex">
              <el-form-item label="Name:">
                <el-input ref="firstField" label="Name" placeholder="Name" v-model="entity.name" size="small"></el-input>
              </el-form-item>
            </el-row>
            <el-row justify="start" type="flex">
              <el-form-item label="Description:">
                <el-input label="Description" v-model="entity.description" size="small"></el-input>
              </el-form-item>
            </el-row>
            <el-row justify="start" type="flex">
              <el-form-item label="internalId:">
                <span style="color: black;">{{entity.id}}</span>
              </el-form-item>
            </el-row>
            <el-row justify="start" type="flex">
              <el-form-item label="Parents:">
                <RoleNameList :holder.sync="entity" fieldName="parents"/>
              </el-form-item>
            </el-row>
          </el-tab-pane>
          <el-tab-pane name="Temporal Constraints" label="Temporal Constraints">
            <TemporalConstraints :tcHolder="entity"/>
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
import RoleNameList from './RoleNameList.vue'
import { Notification } from 'element-ui'

export default {
  name: "Roles",
  data() {
    return {
      entities: [],
      entity: null,
      rowIndex: -1,
      curTab: 'RBAC Role Details',
      multipleSelection: [],
      enableSave: false,
      columns: [{
          prop: "name",
          label: "Name",
          width: "200"
          }, {
          prop: "description",
          label: "Description",
          width: "400"
        }
      ],
     tableProps: {
        border: false,
        stripe: true
     },
      filters: [
        {
          prop: ['name', 'description'],
          value: '',
          filterFn: this.filterRows
        }
      ]
    }
    },
    created() {
      let ftReq = {
                    value: '',
                    contextId: ft.CONTEXT_ID
                  }
      ft.showWait()
      axios.post(ft.FT_BASE_URL+ '/roleSearch', ftReq, ft.AXIOS_FT_CONFIG).then(resp => {
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
      newRole() {
        this.entity = ft.newRole()
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
        let url = ft.FT_BASE_URL+ '/roleUpdate'
        if(this.entity.id == null || this.entity.id == undefined) {
          url = ft.FT_BASE_URL+ '/roleAdd'
          newRole = true
          this.entity.fqcn = 'org.apache.directory.fortress.core.model.Role'
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
          let respPromise = await axios.post(ft.FT_BASE_URL+ '/roleDelete', ftReq, ft.AXIOS_FT_CONFIG)
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
          if(this.searchFamily(filter.value, row.parents)) {
            show = true
          }
        }
        return show
      },
      searchFamily(val, parentsOrChildres) {
        if(parentsOrChildres == null || parentsOrChildres == undefined) {
          return false
        }
        for(let i=0; i < parentsOrChildres.length; i++) {
          let name = parentsOrChildres[i].toLowerCase()
          if(name.indexOf(val) != -1) {
            return true
          }
        }
        return false
      }
    },
    components: {
      SplitPane,
      TemporalConstraints,
      RoleNameList
    }
};
</script>
