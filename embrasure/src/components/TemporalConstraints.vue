<template :tcHolder="tcHolder">
  <div>
    <el-row justify="start" type="flex">
        <el-form-item label="Begin Time:">
            <el-time-select :picker-options="timeSelectOps" v-model="beginTime" size="mini"></el-time-select>
        </el-form-item>
        <el-form-item label="End Time:">
            <el-time-select :picker-options="timeSelectOps" v-model="endTime" size="mini"></el-time-select>
        </el-form-item>
    </el-row>
    <el-row justify="start" type="flex">
        <el-form-item label="Begin Date:">
            <el-date-picker v-model="beginDate" value-format="yyyyMMdd" format="MM/dd/yyyy" type="date"></el-date-picker>
        </el-form-item>
        <el-form-item label="End Date:">
            <el-date-picker v-model="endDate" value-format="yyyyMMdd" format="MM/dd/yyyy" type="date"></el-date-picker>
        </el-form-item>
    </el-row>
    <el-row justify="start" type="flex">
        <el-form-item label="Begin Lock Date:">
            <el-date-picker v-model="beginLockDate" value-format="yyyyMMdd" format="MM/dd/yyyy" type="date"></el-date-picker>
        </el-form-item>
        <el-form-item label="End Lock Date:">
            <el-date-picker v-model="endLockDate" value-format="yyyyMMdd" format="MM/dd/yyyy" type="date"></el-date-picker>
        </el-form-item>
    </el-row>
  </div>
</template>

<script>
/* eslint-disable */
export default {
  name: 'TemporalConstraints',
props: {
  tcHolder: Object,
},
data() {
    return {
        timeSelectOps: {
            start: '00:00',
            end: '23:30'
        }
    }
},
created() {

},
computed: {
    // the below functions are used to convert date and time values in the format fortress stores
    beginTime: {
        get() {
            return this.formatInput(this.tcHolder.beginTime)
        },
        set(newVal) {
            this.tcHolder.beginTime = this.formatOutput(newVal)
        }
    },
    endTime: {
        get() {
            return this.formatInput(this.tcHolder.endTime)
        },
        set(newVal) {
            this.tcHolder.endTime = this.formatOutput(newVal)
        }
    },
    beginDate: {
        get() {
            return this.tcHolder.beginDate
        },
        set(newVal) {
            this.$set(this.tcHolder, 'beginDate', newVal)
        }        
    },
    endDate: {
        get() {
            return this.tcHolder.endDate
        },
        set(newVal) {
            this.$set(this.tcHolder, 'endDate', newVal)
        }        
    },
    beginLockDate: {
        get() {
            return this.tcHolder.beginLockDate
        },
        set(newVal) {
            this.$set(this.tcHolder, 'beginLockDate', newVal)
        }        
    },
    endLockDate: {
        get() {
            return this.tcHolder.endLockDate
        },
        set(newVal) {
            this.$set(this.tcHolder, 'endLockDate', newVal)
        }        
    }
},
methods: {
    formatInput(t) {
        if(t == null) {
            return "00:00"
        }
        return t.substring(0,2) + ':' + t.substring(2)
    },
    formatOutput(t) {
        if(t == null) {
            return "0000"
        }
        return t.substring(0,2) + t.substring(3) // exclude : char
    }

}
};
</script>
