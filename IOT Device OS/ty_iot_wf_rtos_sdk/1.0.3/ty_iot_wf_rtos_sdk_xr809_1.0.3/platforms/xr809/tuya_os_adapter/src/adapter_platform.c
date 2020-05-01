/***********************************************************
*  File: adapter_platform.c
*  Author: nzy
*  Date: 20170921
***********************************************************/
#define _ADAPTER_PLATFORM_GLOBAL
#include "tuya_os_adapter.h"
#include "system/tuya_hal_system_internal.h"
#include "errors_compat.h"



#ifdef __cplusplus
extern "C" {
#endif


/***********************************************************
*************************micro define***********************
***********************************************************/
#define DEF_LOG_BUF_LEN 1024

/***********************************************************
*************************variable define********************
***********************************************************/

/***********************************************************
*************************function define********************
***********************************************************/
/***********************************************************
*  Function: adapter_platform_init
*  Input: none
*  Output: none
*  Return: OPERATE_RET
***********************************************************/
int tuya_os_adapter_init(void)
{
	//this is initial by tuya_base_utilities_init call by tuya_iot_init_params
	
    return OPRT_OK;
}

