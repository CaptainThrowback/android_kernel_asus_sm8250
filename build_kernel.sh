#!/bin/bash

Defconfig_Folder=arch/arm64/configs
Kernel_Root=$PWD
Android_Build=~/android/build/AOSP/android-11
Clang_Google=prebuilts/clang/host
Prebuilt_Clang=clang-r383902
GCC_Google_Arm64=prebuilts/gcc/linux-x86/aarch64
Kernel_Output_Path=out/arch/arm64/boot

echo
echo "Clean Build Directory?"
echo 
PS3='Selection: '
select yn in "Yes" "No"; do
	case $yn in
		Yes)
			echo 
			make clean && make mrproper
			break
			;;
		No)
			break
			;;
	esac
done

echo
echo "Choose Device:"
echo

select device in "ROG Phone 3" "ZenFone 7"; do
	case $device in
		"ROG Phone 3")
			export ASUS_BUILD_PROJECT=ZS661KS
			break
			;;
		"ZenFone 7")
			export ASUS_BUILD_PROJECT=ZS670KS
			break
			;;
	esac
done

echo
echo -e "Building for: $device"
echo

echo
echo "Issue Build Commands"
echo

mkdir -p out
export ARCH=arm64
export SUBARCH=arm64
export CLANG_PATH=$Android_Build/$Clang_Google/linux-x86/$Prebuilt_Clang/bin
export PATH=${CLANG_PATH}:${PATH}
export DTC_EXT=$Kernel_Root/dtc-aosp
export CLANG_TRIPLE=aarch64-linux-gnu-
export CROSS_COMPILE=$Android_Build/$GCC_Google_Arm64/aarch64-linux-android-4.9/bin/aarch64-linux-android-

echo
echo "Choose DEFCONFIG"
echo 

DEFCONFIG=($(find $Defconfig_Folder -type f -exec echo '{}' \; | awk -F'configs/' '{print $NF}'))
select choice in "${DEFCONFIG[@]}"; do
    make CC=clang AR=llvm-ar NM=llvm-nm OBJCOPY=llvm-objcopy OBJDUMP=llvm-objdump STRIP=llvm-strip O=out "$choice"
	break
done

echo
echo "Build The Good Stuff"
echo 

time make CC=clang AR=llvm-ar NM=llvm-nm OBJCOPY=llvm-objcopy OBJDUMP=llvm-objdump STRIP=llvm-strip O=out -j$(($(nproc) * 2))

if [ -e $Kernel_Output_Path/Image ]; then
	echo
	echo "Compress Kernel Image"
	echo 
	gzip -9 -k -f $Kernel_Output_Path/Image
	echo
	echo "Compile DTBs"
	echo
	find $Kernel_Output_Path/dts -name '*.dtb' -exec cat {} + > $Kernel_Output_Path/dtb.img
	echo
	echo "Build Complete!"
	echo
else
	echo
	echo "Build Failed. See above error(s) for details."
	echo
fi
