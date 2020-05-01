
TUYA_PLATFORM_DIR := $(dir $(lastword $(MAKEFILE_LIST)))/../


# tuya os adapter includes
TUYA_PLATFORM_CFLAGS := -I$(TUYA_PLATFORM_DIR)/tuya_os_adapter/include
TUYA_PLATFORM_CFLAGS += -I$(TUYA_PLATFORM_DIR)/tuya_os_adapter/include/driver
TUYA_PLATFORM_CFLAGS += -I$(TUYA_PLATFORM_DIR)/tuya_os_adapter/include/system



TUYA_PLATFORM_CFLAGS += -mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=softfp -c -gdwarf-2 -fno-common -fmessage-length=0 -fno-exceptions -ffunction-sections -fdata-sections -fomit-frame-pointer -Wall -Wpointer-arith -Wno-error=unused-function -MMD -MP -Os -std=gnu99
