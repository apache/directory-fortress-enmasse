import { Loading, Notification } from 'element-ui'

export var FT_BASE_URL = '/fortress-rest'
export var AXIOS_FT_CONFIG = {headers: {'Content-Type': 'application/json', 'Accept': 'application/json'}}
export var CONTEXT_ID = 'HOME'

var loadingWidget = null;
export function showWait() {
    loadingWidget = Loading.service({
        lock: true,
        text: 'Loading',
        spinner: 'el-icon-loading',
        background: 'rgba(0, 0, 0, 0)',
        fullscreen: true
      })
 }

export function closeWait() {
     if(loadingWidget != null) {
         loadingWidget.close()
         loadingWidget = null
     }
 }

 export function showSuccess(msg) {
     Notification.success({message: msg})
 }

 export function showErr(msg, e) {
     // close if the wait screen is still present
     closeWait()
     if(msg === undefined || msg === null) {
         msg = ''
     }
     if(e !== null && e !== undefined && e.response !== undefined) {
        if(e.response.data !== undefined) {
            msg = msg + ' (' + e.response.data.detail + ')'
        }
     }
     Notification.warning({message: msg, duration: 10000})
 }

 export function focusFirstField(component) {
    component.$nextTick(function(){
        component.$refs.firstField.focus()
    })
 }

 export function newUser() {
    return {
        address: {
            addresses: null,
            building: null,
            city: null,
            country: null,
            departmentNumber: null,
            postOfficeBox: null,
            postalCode: null,
            roomNumber: null,
            state: null
        },
        adminRoles: null,
        adminSession: null,
        beginDate: null,
        beginLockDate: null,
        beginTime: null,
        cn: null,
        contextId: null,
        dayMask: null,
        description: null,
        displayName: null,
        dn: null,
        emails: null,
        employeeType: null,
        endDate: null,
        endLockDate: null,
        endTime: null,
        fqcn: null,
        gecos: null,
        gidNumber: null,
        homeDirectory: null,
        internalId: null,
        jpegPhoto: null,
        locked: false,
        loginShell: null,
        mobiles: null,
        modCode: null,
        modId: null,
        name: null,
        newPassword: null,
        ou: null,
        password: null,
        phones: null,
        pwPolicy: null,
        reset: false,
        roles: null,
        sequenceId: 0,
        sn: null,
        system: false,
        timeout: 60,
        title: null,
        uidNumber: null,
        userId: null
    }
 }

 export function newRole() {
     return {
        modCode: null,
        modId: null,
        adminSession: null,
        sequenceId: 0,
        contextId: null,
        id: null,
        name: null,
        description: null,
        dn: null,
        occupants: null,
        parents: [],
        children: [],
        beginTime: null,
        endTime: null,
        beginDate: null,
        endDate: null,
        beginLockDate: null,
        endLockDate: null,
        dayMask: null,
        gidNumber: null,
        timeout: 0
        }
 }

 export function newPermObject() {
     return {
        modCode: null,
        modId: null,
        adminSession: null,
        sequenceId: 0,
        contextId: null,
        admin: false,
        internalId: null,
        objName: null,
        description: null,
        props: {
            fqcn: 'org.apache.directory.fortress.core.model.Props'
        },
        ou: null,
        type: null,
        dn: null
    }
 }

 export function newPermission() {
     return {
        modCode: null,
        modId: null,
        adminSession: null,
        sequenceId: 0,
        contextId: null,
        admin: false,
        internalId: null,
        opName: null,
        objName: null,
        objId: null,
        abstractName: null,
        type: null,
        dn: null,
        description: null,
        props: {
            fqcn: 'org.apache.directory.fortress.core.model.Props'
        },
        roles: [],
        users: [],
        paSets: []
    }
 }