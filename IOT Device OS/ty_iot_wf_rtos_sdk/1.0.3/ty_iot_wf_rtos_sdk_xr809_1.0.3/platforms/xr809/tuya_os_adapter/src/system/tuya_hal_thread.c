
#include <FreeRTOS.h>
#include <task.h>
#include "tuya_hal_thread.h"
#include "../errors_compat.h"

#include "kernel/os/os_thread.h"
#include "sys/defs.h"


int tuya_hal_thread_create(THREAD_HANDLE* thread,
                            const char* name,
                            uint32_t stack_size,
                            uint32_t priority,
                            THREAD_FUNC_T func,
                            void* const arg)
{
    BaseType_t ret = 0;
#if 0
    ret = xTaskCreate(func, name, stack_size/sizeof(portSTACK_TYPE), arg, priority, thread);
    if (ret != pdPASS) {
        return OPRT_THRD_CR_FAILED;
    }
#else
	if(!thread || !func)
    {
        return OPRT_INVALID_PARM;
    }
	
	ret = OS_ThreadCreate((OS_Thread_t *)thread, name,
                func, arg, priority, stack_size);
	if(ret != OS_OK)
    {
        //*thread = NULL;
        return OPRT_THRD_CR_FAILED;
    }
#endif
	
    return OPRT_OK;
}

int tuya_hal_thread_release(THREAD_HANDLE thread)
{
    if (NULL == thread) {
        return OPRT_INVALID_PARM;
    }

    // delete thread process 
    //vTaskDelete(thread);
	OS_ThreadDelete((OS_Thread_t *)&thread);

    return OPRT_OK;
}

int tuya_hal_thread_is_self(THREAD_HANDLE thread, bool* is_self)
{
    if (NULL == thread || NULL == is_self) {
        return OPRT_INVALID_PARM;
    }

    //THREAD_HANDLE self_handle = xTaskGetCurrentTaskHandle();
    THREAD_HANDLE self_handle = OS_ThreadGetCurrentHandle();
    if (NULL == self_handle) {
        return OPRT_COM_ERROR;
    }

    *is_self = (thread == self_handle);

    return OPRT_OK;
}

int tuya_hal_thread_set_self_name(const char* name)
{
    return OPRT_OK;
}

