#!/bin/sh

APP_PATH=$1
APP_NAME=$2
APP_VERSION=$3
echo APP_PATH=$APP_PATH
echo APP_NAME=$APP_NAME
echo APP_VERSION=$APP_VERSION


fatal() {
    echo -e "\033[0;31merror: $1\033[0m"
    exit 1
}


[ -z $APP_PATH ] && fatal "no app path!"
[ -z $APP_NAME ] && fatal "no app name!"
[ -z $APP_VERSION ] && fatal "no version!"


cd `dirname $0`

TARGET_PLATFORM=arm-linux-gnueabihf-gcc-6.3.1
TOOLCHAIN_PATH=$(pwd)/platforms/$TARGET_PLATFORM/toolchain

# 解压工具链
TOOLCHAIN_GCC=${TARGET_PLATFORM%-*}
if [ "$(find $TOOLCHAIN_PATH -name $TOOLCHAIN_GCC)" ]; then
        echo ""
else
        TMP_VAR=${TOOLCHAIN_GCC%-*}
        echo "tar -axf $TMP_VAR.tar.gz"
        echo "....."
        tar -axf $TOOLCHAIN_PATH/$TMP_VAR.tar.gz -C $TOOLCHAIN_PATH/
fi

. $TOOLCHAIN_PATH/build_path
if [ -z "$TUYA_SDK_BUILD_PATH" ];then
    COMPILE_PREX=
else
    COMPILE_PREX=$(pwd)/platforms/$TARGET_PLATFORM/toolchain/$TUYA_SDK_BUILD_PATH
fi

cd $APP_PATH
make COMPILE_PREX=$COMPILE_PREX APP_BIN_NAME=$APP_NAME USER_SW_VER=$APP_VERSION all

