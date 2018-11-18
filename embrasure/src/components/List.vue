<template :holder="holder" :fieldName="fieldName">
  <div style="min-width: 10px; min-height: 10px;">
    <table>
        <tr style="line-height: 25px;"
          v-for="(n, index) in items"
          :key="index"
          :label="n"
          :value="index">
          <td>
              <span class="option_span_item">{{index+1}}.</span>
          </td>
          <td>
            <input type="text" :value="n" :ref="fieldName+index" @input="updateItem(index)"/><i @click="deleteItem(index)" style="color: red; padding-left: 1px;" class="el-icon-remove"></i>
          </td>
        </tr>
      </table>
      <div style="padding: 1px;"/>
      <el-button type="success" round size="mini" @click="addItem">+</el-button>
  </div>
</template>

<script>
/* eslint-disable */
export default {
  name: 'List',
props: {
  holder: Object,
  fieldName: String
},
data() {
    return {
    }
},
created() {

},
computed: {
    items: {
        get() {
            let arr = this.holder[this.fieldName]
            if(arr == null) {
                arr = []
            }

            return arr
        },
        set(newVal) {
            // ignore
        }
    }
},
methods: {
    addItem() {
        let arr = this.holder[this.fieldName]
        if(arr == null) {
            this.$set(this.holder, this.fieldName, [])
            arr = this.holder[this.fieldName]
        }
        arr.push('')
    },
    deleteItem(index) {
        let arr = this.holder[this.fieldName]
        if(arr != null) {
            arr.splice(index, 1)
        }
    },
    updateItem(index) {
        let inputRef = this.fieldName + index
        let newVal = this.$refs[inputRef][0].value
        let arr = this.holder[this.fieldName]
        if(arr != null) {
            arr[index] = newVal
        }        
    }
}
};
</script>
