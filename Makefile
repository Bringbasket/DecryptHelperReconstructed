ARCHS = arm64
TARGET = iphone:clang:latest:14.0
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = decrypt_helper

decrypt_helper_FILES = \
	Source/DHBootstrap.m \
	Source/DHConfig.m \
	Source/DHCommonCrypto.m \
	Source/DHAsymmetric.m \
	Source/DHKeychain.m \
	Source/DHFileHooks.m \
	Source/DHEVP.m \
	Source/DHLogStore.m \
	Source/DHNetwork.m \
	Source/DHSpoof.m \
	Source/DHHTTPServer.m \
	Source/DHImageInventory.m \
	Source/DHDump.m \
	Vendor/fishhook/fishhook.c

decrypt_helper_CFLAGS = -IHeaders -IVendor/fishhook -Wno-deprecated-declarations
decrypt_helper_OBJCFLAGS = -fobjc-arc
decrypt_helper_FRAMEWORKS = Foundation UIKit Security
decrypt_helper_INSTALL_PATH = /usr/lib/IOSDecryptHub
decrypt_helper_LDFLAGS = -Wl,-install_name,@executable_path/decrypt_helper.dylib

include $(THEOS_MAKE_PATH)/library.mk
