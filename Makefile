
ARCH := $(shell adb shell getprop ro.product.cpu.abi)

all: build

build:
	ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./Android.mk APP_ABI=$(ARCH)

push: build
	adb push libs/$(ARCH)/poc /data/local/tmp/poc

clean:
	rm -rf libs
	rm -rf obj

