/***********************************************************
*  File: uni_output.c
*  Author: nzy
*  Date: 20170921
***********************************************************/
#include "FreeRTOS.h"
#include "tuya_hal_system.h"

#define _UNI_OUTPUT_GLOBAL
#ifdef CONFIG_PLATFORM_8195A
#include "rtl8195a.h"
#endif

#ifdef CONFIG_PLATFORM_8711B
#include "rtl8710b.h"
#endif
#include "tuya_hal_system.h"
#include "tuya_hal_network.h"
#include "../errors_compat.h"

/***********************************************************
*************************micro define***********************
***********************************************************/
/* 终端输出函数 */
#ifdef CONFIG_PLATFORM_8195A
    #define OutputPrint DBG_8195A
#endif

#ifdef CONFIG_PLATFORM_8711B
    #define OutputPrint DiagPrintf
#endif

#define OutputPrint printf

/***********************************************************
*************************variable define********************
***********************************************************/

/***********************************************************
*************************function define********************
***********************************************************/

/***********************************************************
*  Function: uni_log_output 
*  Input: str
*  Output: none
*  Return: none
***********************************************************/
void tuya_hal_output_log(const char *str)
{
    OutputPrint("%s",str);
}

