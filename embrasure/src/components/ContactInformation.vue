<template :entity="entity">
    <div>
        <el-row justify="start" type="flex">
            <el-form-item label="Emails:">
                <List :holder.sync="entity" fieldName="emails"/>
            </el-form-item>
            <el-form-item label="Phones:">
                <List :holder.sync="entity" fieldName="phones"/>
            </el-form-item>
        </el-row>
        <el-row justify="start" type="flex">
            <el-form-item label="Mobiles:">
                <List :holder.sync="entity" fieldName="mobiles"/>
            </el-form-item>
        </el-row>
        <el-row justify="start" type="flex">
            <el-form-item label="City:">
                <el-input label="City" placeholder="" v-model="entity.address.city" size="small"></el-input>
            </el-form-item>
            <el-form-item label="State:">
                <el-input label="State" placeholder="" v-model="entity.address.state" size="small"></el-input>
            </el-form-item>
        </el-row>
        <el-row justify="start" type="flex">
            <el-form-item label="Country:">
                <el-input label="Country" placeholder="" v-model="entity.address.country" size="small"></el-input>
            </el-form-item>
            <el-form-item label="Postal Code:">
                <el-input label="Postal Code" placeholder="" v-model="entity.address.postalCode" size="small"></el-input>
            </el-form-item>
        </el-row>
        <el-row justify="start" type="flex">
            <el-form-item label="Post Office Box:">
                <el-input label="Post Office Box" placeholder="" v-model="entity.address.postOfficeBox" size="small"></el-input>
            </el-form-item>
            <el-form-item label="Building:">
                <el-input label="Building" placeholder="" v-model="entity.address.building" size="small"></el-input>
            </el-form-item>
        </el-row>
        <el-row justify="start" type="flex">
            <el-form-item label="Department Number:">
                <el-input label="Department Number" placeholder="" v-model="entity.address.departmentNumber" size="small"></el-input>
            </el-form-item>
            <el-form-item label="Room Number:">
                <el-input label="Room Number" placeholder="" v-model="entity.address.roomNumber" size="small"></el-input>
            </el-form-item>
        </el-row>
        <el-row justify="start" type="flex">
            <el-form-item label="Addresses:">
                <List :holder.sync="entity.address" fieldName="addresses"/>
            </el-form-item>
        </el-row>
    </div>
</template>

<script>
/* eslint-disable */
import List from './List.vue'

export default {
  name: 'ContactInformation',
props: {
  entity: Object,
},
data() {
    return {
    }
},
created() {
let address = {
                addresses: null,
                city: null,
                state: null,
                country: null,
                postalCode: null,
                postOfficeBox: null,
                building: null,
                departmentNumber: null,
                roomNumber: null
            }
    if(this.entity.address == undefined || this.entity.address == null) {
        this.$set(this.entity, 'address', address)
    }
},
computed: {

},
methods: {
},
components: {
    List
}
};
</script>
