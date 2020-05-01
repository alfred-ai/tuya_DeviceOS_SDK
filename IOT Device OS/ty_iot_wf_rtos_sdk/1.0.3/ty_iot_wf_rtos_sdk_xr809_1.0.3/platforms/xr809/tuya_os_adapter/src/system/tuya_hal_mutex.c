/***********************************************************
*  File: uni_mutex.c
*  Author: nzy
*  Date: 120427
***********************************************************/
#define _UNI_MUTEX_GLOBAL
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"
#include "tuya_hal_memory.h"
#include "tuya_hal_mutex.h"
#include "tuya_hal_system_internal.h"
#include "../errors_compat.h"
#include "kernel/os/os_mutex.h"

/***********************************************************
*************************micro define***********************
***********************************************************/
#if 0
typedef xSemaphoreHandle THRD_MUTEX;

typedef struct
{
    THRD_MUTEX mutex;
}MUTEX_MANAGE,*P_MUTEX_MANAGE;
#endif
typedef OS_Mutex_t MUTEX_MANAGE;
typedef OS_Mutex_t *P_MUTEX_MANAGE;

/***********************************************************
*************************variable define********************
***********************************************************/

/***********************************************************
*************************function define********************
***********************************************************/

/***********************************************************
*  Function: CreateMutexAndInit 创建一个互斥量并初始化
*  Input: none
*  Output: pMutexHandle->新建的互斥量句柄
*  Return: OPERATE_RET
*  Date: 120427
***********************************************************/
int tuya_hal_mutex_create_init( MUTEX_HANDLE *pMutexHandle)
{
    if(!pMutexHandle)
        return OPRT_INVALID_PARM;
    
    P_MUTEX_MANAGE pMutexManage = NULL;
    pMutexManage = (P_MUTEX_MANAGE)tuya_hal_system_malloc(sizeof(MUTEX_MANAGE));
    if(!(pMutexManage))
        return OPRT_MALLOC_FAILED;
	
    memset(pMutexManage, 0, sizeof(MUTEX_MANAGE));

#if defined(CREATE_RECURSION_MUTEX)
	OS_RecursiveMutexCreate(pMutexManage);
    //pMutexManage->mutex = xSemaphoreCreateRecursiveMutex();
#else
	OS_MutexCreate(pMutexManage);
    //pMutexManage->mutex = xSemaphoreCreateMutex();
#endif
    //if(NULL == pMutexManage->mutex) {
	if(NULL == pMutexManage->handle) {
        return OPRT_INIT_MUTEX_FAILED;
    }

    *pMutexHandle = (MUTEX_HANDLE)pMutexManage;

    return OPRT_OK;
}

/***********************************************************
*  Function: MutexLock 加锁
*  Input: mutexHandle->互斥量句柄
*  Output: none
*  Return: OPERATE_RET
*  Date: 120427
***********************************************************/
int tuya_hal_mutex_lock( const MUTEX_HANDLE mutexHandle)
{
    if(!mutexHandle)
        return OPRT_INVALID_PARM;

    P_MUTEX_MANAGE pMutexManage;
    pMutexManage = (P_MUTEX_MANAGE)mutexHandle;
    
    BaseType_t ret;
#if 0
    ret = xSemaphoreTake(pMutexManage->mutex, portMAX_DELAY);
    if(pdTRUE != ret) {
        return OPRT_MUTEX_LOCK_FAILED;
    }
#else
	ret = OS_MutexLock(pMutexManage, portMAX_DELAY);
	if(OS_OK != ret) {
        return OPRT_MUTEX_LOCK_FAILED;
    }
#endif
    return OPRT_OK;
}

/***********************************************************
*  Function: MutexUnLock 解锁
*  Input: mutexHandle->互斥量句柄
*  Output: none
*  Return: OPERATE_RET
*  Date: 120427
***********************************************************/
int tuya_hal_mutex_unlock( const MUTEX_HANDLE mutexHandle)
{
    if(!mutexHandle)
        return OPRT_INVALID_PARM;
    
    P_MUTEX_MANAGE pMutexManage;
    pMutexManage = (P_MUTEX_MANAGE)mutexHandle;
    
    BaseType_t ret;
#if 0
    if(FALSE == tuya_hal_system_isrstatus()) {
        ret = xSemaphoreGive(pMutexManage->mutex);
    }else {
        signed portBASE_TYPE xHigherPriorityTaskWoken = pdFALSE;
        ret = xSemaphoreGiveFromISR(pMutexManage->mutex,\
                                    &xHigherPriorityTaskWoken);
        portEND_SWITCHING_ISR(xHigherPriorityTaskWoken);
    }
    if(pdTRUE != ret) {
        return OPRT_MUTEX_UNLOCK_FAILED;
    }
#else
	ret = OS_MutexUnlock(pMutexManage);
	if(OS_OK != ret) {
        return OPRT_MUTEX_UNLOCK_FAILED;
    }
#endif
	
    return OPRT_OK;
}

/***********************************************************
*  Function: ReleaseMutexManage 释放互斥锁管理结构资源
*  Input: mutexHandle->互斥量句柄
*  Output: none
*  Return: OPERATE_RET
*  Date: 120427
***********************************************************/
int tuya_hal_mutex_release( const MUTEX_HANDLE mutexHandle)
{
    if(!mutexHandle)
        return OPRT_INVALID_PARM;

    P_MUTEX_MANAGE pMutexManage;
    pMutexManage = (P_MUTEX_MANAGE)mutexHandle;
    
    //vSemaphoreDelete(pMutexManage->mutex);
    OS_MutexDelete(pMutexManage);

    tuya_hal_system_free(mutexHandle);

    return OPRT_OK;
}


