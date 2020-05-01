/***********************************************************
*  File: uni_semaphore.c
*  Author: nzy
*  Date: 120427
***********************************************************/
#define _UNI_SEMAPHORE_GLOBAL
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"
#include "tuya_hal_memory.h"
#include "tuya_hal_semaphore.h"
#include "tuya_hal_system_internal.h"
#include "../errors_compat.h"
#include "kernel/os/os_semaphore.h"

/***********************************************************
*************************micro define***********************
***********************************************************/

#if 0
#define LOGD PR_DEBUG
#define LOGT PR_TRACE
#define LOGN PR_NOTICE
#define LOGE PR_ERR
#else
//#define LOGD(...) DiagPrintf("[SEM DEBUG]" __VA_ARGS__)
//#define LOGT(...) DiagPrintf("[SEM TRACE]" __VA_ARGS__)
//#define LOGN(...) DiagPrintf("[SEM NOTICE]" __VA_ARGS__)
//#define LOGE(...) DiagPrintf("[SEM ERROR]" __VA_ARGS__)

#define LOGD(fmt, arg...) printf(fmt, ##arg)
#define LOGT(fmt, arg...) printf(fmt, ##arg)
#define LOGN(fmt, arg...) printf(fmt, ##arg)
#define LOGE(fmt, arg...) printf(fmt, ##arg)


#endif


#if 0
typedef struct
{
    xSemaphoreHandle sem;
}SEM_MANAGE,*P_SEM_MANAGE;
#endif

typedef OS_Semaphore_t SEM_MANAGE;
typedef OS_Semaphore_t *P_SEM_MANAGE;


/***********************************************************
*************************variable define********************
***********************************************************/

/***********************************************************
*************************function define********************
***********************************************************/
/***********************************************************
*  Function: CreateSemaphore 创建一个信号量
*  Input: reqSize->申请的内存大小
*  Output: none
*  Return: NULL失败，非NULL成功
*  Date: 120427
***********************************************************/
static SEM_HANDLE CreateSemaphore(void)
{
    P_SEM_MANAGE pSemManage;
    
    pSemManage = (P_SEM_MANAGE)tuya_hal_system_malloc(sizeof(SEM_MANAGE));

    return (SEM_HANDLE)pSemManage;
}

/***********************************************************
*  Function: InitSemaphore
*  Input: semHandle->信号量操作句柄
*         semCnt
*         sem_max->no use for linux os
*  Output: none
*  Return: OPERATE_RET
*  Date: 120427
***********************************************************/
static int InitSemaphore(const SEM_HANDLE semHandle, const uint32_t semCnt,\
                                 const uint32_t sem_max)
{
    if(!semHandle)
        return OPRT_INVALID_PARM;
        
    P_SEM_MANAGE pSemManage;
    pSemManage = (P_SEM_MANAGE)semHandle;
#if 0
    pSemManage->sem = xSemaphoreCreateCounting(sem_max, semCnt);
    if(NULL == pSemManage->sem) {
        return OPRT_INIT_SEM_FAILED;
    }
#else
	OS_SemaphoreCreate(pSemManage, semCnt, sem_max);
	if(NULL == pSemManage->handle) {
        return OPRT_INIT_SEM_FAILED;
    }
#endif
    return OPRT_OK;
}

int tuya_hal_semaphore_create_init(SEM_HANDLE *pHandle, const uint32_t semCnt, \
                          const uint32_t sem_max)
{
    if(NULL == pHandle)
    {
        LOGE("invalid param\n");
        return OPRT_INVALID_PARM;
    }

    *pHandle = CreateSemaphore();
    if(*pHandle == NULL)
    {
        LOGE("malloc fails\n");
        return OPRT_MALLOC_FAILED;
    }

    int ret = InitSemaphore(*pHandle, semCnt, sem_max);

    if(ret != OPRT_OK)
    {
        tuya_hal_system_free(*pHandle);
        *pHandle = NULL;
        LOGE("semaphore init fails %d %d\n", semCnt, sem_max);
        return ret;
    }

    return OPRT_OK;
}

/***********************************************************
*  Function: WaitSemaphore
*  Input: semHandle->信号量操作句柄
*  Output: none
*  Return: OPERATE_RET
*  Date: 120427
***********************************************************/
int tuya_hal_semaphore_wait(const SEM_HANDLE semHandle)
{
    if(!semHandle)
        return OPRT_INVALID_PARM;

    P_SEM_MANAGE pSemManage;
    pSemManage = (P_SEM_MANAGE)semHandle;

    BaseType_t ret;
#if 0
    ret = xSemaphoreTake(pSemManage->sem, portMAX_DELAY);
    if(pdTRUE != ret) {
        return OPRT_WAIT_SEM_FAILED;
    }
#else
	ret = OS_SemaphoreWait(pSemManage, OS_WAIT_FOREVER);
	if(OS_OK != ret) {
        return OPRT_WAIT_SEM_FAILED;
    }
#endif
    return OPRT_OK;
}

/***********************************************************
*  Function: WaitSemaphore_with_timeout
*  Input: semHandle->信号量操作句柄 timeout->超时时间
*  Output: none
*  Return: OPERATE_RET
*  Date: 120427 added by tingle for xr872
***********************************************************/
int tuya_hal_semaphore_wait_with_timeout(const SEM_HANDLE semHandle,const uint32_t timeout)
{
    if(!semHandle) 
        return OPRT_INVALID_PARM;

    P_SEM_MANAGE pSemManage;
    pSemManage = (P_SEM_MANAGE)semHandle;

    BaseType_t ret;
    ret = OS_SemaphoreWait(pSemManage, timeout);
    if(OS_OK != ret) {
        return OPRT_WAIT_SEM_FAILED;
    }

    return OPRT_OK;
}

/***********************************************************
*  Function: PostSemaphore
*  Input: semHandle->信号量操作句柄
*  Output: none
*  Return: OPERATE_RET
*  Date: 120427
***********************************************************/
int tuya_hal_semaphore_post(const SEM_HANDLE semHandle)
{
    if(!semHandle)
        return OPRT_INVALID_PARM;

    P_SEM_MANAGE pSemManage;
    pSemManage = (P_SEM_MANAGE)semHandle;

    BaseType_t ret;
#if 0
    if(FALSE == tuya_hal_system_isrstatus()) {
        ret = xSemaphoreGive(pSemManage->sem);
    }else {
        signed portBASE_TYPE xHigherPriorityTaskWoken = pdFALSE;
        ret = xSemaphoreGiveFromISR(pSemManage->sem,
                                    &xHigherPriorityTaskWoken);
        portEND_SWITCHING_ISR(xHigherPriorityTaskWoken);
    }

    if(pdTRUE != ret) {
        return OPRT_POST_SEM_FAILED;
    }
#else
	ret = OS_SemaphoreRelease(pSemManage);
    if(OS_OK != ret) {
        return OPRT_POST_SEM_FAILED;
    }
#endif
    return OPRT_OK;
}

/***********************************************************
*  Function: ReleaseSemaphore
*  Input: semHandle->信号量操作句柄
*  Output: none
*  Return: OPERATE_RET
*  Date: 120427
***********************************************************/
int tuya_hal_semaphore_release(const SEM_HANDLE semHandle)
{
    if(!semHandle)
        return OPRT_INVALID_PARM;

    P_SEM_MANAGE pSemManage;
    pSemManage = (P_SEM_MANAGE)semHandle;

    //vSemaphoreDelete(pSemManage->sem);
	OS_SemaphoreDelete(pSemManage);
    tuya_hal_system_free(semHandle); // 释放信号量管理结构

    return OPRT_OK;
}


