#
# Rules for building application
#

# ----------------------------------------------------------------------------
# project local config
# ----------------------------------------------------------------------------
include localconfig.mk

# ----------------------------------------------------------------------------
# common rules
# ----------------------------------------------------------------------------
ROOT_PATH := ../../..
TUYA_IOT_ROOT_DIR := $(ROOT_PATH)/../../..

include $(ROOT_PATH)/gcc.mk
# ----------------------------------------------------------------------------
# project and objects
# ----------------------------------------------------------------------------
PROJECT := tuya
APP_BIN_NAME ?= xr809_common_lowpower_ty
USER_SW_VER ?= 9.9.9
USER_FULL_SW_VER ?= $(USER_SW_VER)
$(warning $(APP_BIN_NAME) $(USER_SW_VER) $(USER_FULL_SW_VER))

include $(TUYA_IOT_ROOT_DIR)/build/build_param

#compile option
CC_FLAGS += $(TY_IOT_CFLAGS)
CC_FLAGS += \
	-DAPP_BIN_NAME=\"$(APP_BIN_NAME)\" \
	-DUSER_SW_VER=\"$(USER_SW_VER)\" \
	-DUSER_FULL_SW_VER=\"$(USER_FULL_SW_VER)\" \

#include path
INCLUDE_PATHS += -I$(ROOT_PATH)/project/$(PROJECT)/
INCLUDE_PATHS += $(TY_IOT_INC_DIRS)

#src path
DIRS_IGNORE := ../gcc% ../image% $(ROOT_PATH)/project/common/board/%
DIRS_ALL := $(shell find $(ROOT_PATH)/project/common -type d)
DIRS := $(filter-out $(DIRS_IGNORE),$(DIRS_ALL))
DIRS += $(ROOT_PATH)/project/common/board/$(__PRJ_CONFIG_BOARD)

DIRS += $(ROOT_PATH)/project/$(PROJECT)/

DIRS += $(TY_IOT_SRC_DIRS)

SRCS := $(basename $(foreach dir,$(DIRS),$(wildcard $(dir)/*.[csS])))

OBJS := $(addsuffix .o,$(SRCS))

# extra libs
PRJ_EXTRA_LIBS := -ltuya_iot
# ----------------------------------------------------------------------------
# override project variables
# ----------------------------------------------------------------------------
# linker script path/file
#   - relative to "./"
#   - define your own "LINKER_SCRIPT_PATH" and/or "LINKER_SCRIPT" to override
#     the default one
# LINKER_SCRIPT_PATH := .
# LINKER_SCRIPT :=

# image config path/file
#   - relative to "../image/xxxxx/", eg. "../image/xr871/"
#   - define your own "IMAGE_CFG_PATH" and/or "IMAGE_CFG" to override the
#     default one
# IMAGE_CFG_PATH := .
# IMAGE_CFG :=

# image name, default to xr_system
# IMAGE_NAME :=

# project make rules
include $(PRJ_MAKE_RULES)
