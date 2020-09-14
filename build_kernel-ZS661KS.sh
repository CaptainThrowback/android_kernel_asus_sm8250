#!/bin/bash

Kernel_Root=~/android/build/kernel/asus/sm8250
Android_Build=~/android/build/omni/android-10
Clang_Google=prebuilts/clang/host
Prebuilt_Clang=clang-r383902c
GCC_Google_Arm64=prebuilts/gcc/linux-x86/aarch64

echo
echo "Clean Build Directory"
echo 

make clean && make mrproper

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
# export CROSS_COMPILE_ARM32=~/Android_Build/GCC_Google_Arm32/arm-linux-androideabi-4.9/bin/arm-linux-androideabi-
# export LD_LIBRARY_PATH=~/Android_Build/Clang_Google/linux-x86/clang-r383902c/lib64:$LD_LIBRARY_PATH

echo
echo "Set DEFCONFIG"
echo 
make CC=clang AR=llvm-ar NM=llvm-nm OBJCOPY=llvm-objcopy OBJDUMP=llvm-objdump STRIP=llvm-strip O=out vendor/ZS661KS-perf_defconfig

echo
echo "Build The Good Stuff"
echo 

make CC=clang AR=llvm-ar NM=llvm-nm OBJCOPY=llvm-objcopy OBJDUMP=llvm-objdump STRIP=llvm-strip O=out -j4

echo
echo "Compile DTBs"
echo

find out/arch/arm64/boot/dts -name '*.dtb' -exec cat {} + > out/arch/arm64/boot/dtb.img