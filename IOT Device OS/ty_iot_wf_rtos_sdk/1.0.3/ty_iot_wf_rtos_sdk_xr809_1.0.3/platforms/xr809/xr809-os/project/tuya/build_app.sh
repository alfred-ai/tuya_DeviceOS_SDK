#!/bin/sh
#BUILD_TYPE=8710_1M
BUILD_TYPE=8710_2M

APP_DEBUG=1

if [ -z "$1" ];then
        echo "please input the app bin name(no suffix \".bin\")!!!"
        exit 1
else
        APP_BIN_NAME=$1
fi

if [ -z "$2" ];then
        echo "please input the app sw version(for example:the format is "1.1.1")!!!"
        exit 1
else
        USER_SW_VER=$2
fi
#mkdir tuya_user/$APP_BIN_NAME/output/$USER_SW_VER
# $3 compile parameter command as user set,for example clean and so on.
if [ -z "$3" ] || [ "$3" = "release" ];then
	USER_DEF_CMD=build
else
	USER_DEF_CMD=$3
fi

echo ""
echo "start..."
echo ""
set -e

if [ -e "./image/xr871/xr_system.img" ]; then
	if [ "$3" = "clean" ];then
		echo ""
	else
		rm ./image/xr871/xr_system.img
	fi
fi

#tuya_main
if [ -e "./tuya_common/src/tuya_main.o" ]; then
	rm -r ./tuya_common/src/tuya_main.o
fi 
if [ -e "./tuya_common/src/tuya_main.d" ]; then
	rm -r ./tuya_common/src/tuya_main.d
fi

#tuya_user
if [ -e "./tuya_user/$APP_BIN_NAME/src/tuya_device.o" ]; then
	rm -r ./tuya_user/$APP_BIN_NAME/src/*.o
	rm -r ./tuya_user/$APP_BIN_NAME/src/*.d
fi


if [ -e "../../src/tuya_iot/src/tuya_iot_sdk/com_sdk/tuya_iot_com_api.o"  ]; then
	rm  ../../src/tuya_iot/src/tuya_iot_sdk/com_sdk/tuya_iot_com_api.o
	rm  ../../src/tuya_iot/src/tuya_iot_sdk/com_sdk/tuya_iot_com_api.d
fi

if [ -z "$3" ];then
        echo ""
elif [ "$3" = "release" ];then
		APP_DEBUG=0
else
		echo "make lib clean"
        make $USER_DEF_CMD -C ../../src/tuya_iot/
fi



echo "hjdfhdjfhkdfhdkjhj"
make APP_BIN_NAME=$APP_BIN_NAME USER_SW_VER=$USER_SW_VER $USER_DEF_CMD BUILD_TYPE=$BUILD_TYPE  APP_DEBUG=$APP_DEBUG -C ./gcc
cd ./gcc
make image_xz
cd ..

if [ ! -d "./tuya_user/$APP_BIN_NAME/output/$USER_SW_VER" ]; then
	mkdir -p ./tuya_user/$APP_BIN_NAME/output/$USER_SW_VER
fi


if [ -e "./image/xr871/xr_system.img" ]; then
	cp ./image/xr871/xr_system.img ./tuya_user/$APP_BIN_NAME/output/$USER_SW_VER/$APP_BIN_NAME"_"$USER_SW_VER.img
	cp ./image/xr871/xr_system_img_xz.img ./tuya_user/$APP_BIN_NAME/output/$USER_SW_VER/$APP_BIN_NAME"_ug_"$USER_SW_VER.bin
	
	cp ./image/xr871/xr_system.img ../../combine/
	cd ../../combine/
	./phoenixMC -g 1 -G combineImage.cimg
	cp ./combineImage.cimg ../project/tuya/tuya_user/$APP_BIN_NAME/output/$USER_SW_VER/$APP_BIN_NAME"_QIO_"$USER_SW_VER.bin
	#rm ./xr_system.img ./combineImage.cimg
	#./phoenixMC -i combineImage.cimg
fi

if [ $APP_DEBUG  = 1 ];then
		echo "COMPILE DEBUG VERSION"
else
		echo "COMPILE RELEASE VERSION"
fi
echo "*****************************COMPILE SUCCESS!***********************************"	