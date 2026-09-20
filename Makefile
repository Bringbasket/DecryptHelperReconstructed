ARCHS ?= arm64
TARGET ?= iphone:clang:latest:14.0
THEOS_PACKAGE_SCHEME ?= rootless

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = decrypt_helper

decrypt_helper_FILES = \
	Source/DHBootstrap.m \
	Source/DHConfig.m \
	Source/DHCommonCrypto.m \
	Source/DHAsymmetric.m \
	Source/DHDynamic.m \
	Source/DHKeychain.m \
	Source/DHFileHooks.m \
	Source/DHEVP.m \
	Source/DHFloatingUI.m \
	Source/DHLogStore.m \
	Source/DHHookRegistry.m \
	Source/DHNetwork.m \
	Source/DHNetworkExtensions.m \
	Source/DHWebKitProbe.m \
	Source/DHWebSocket.m \
	Source/DHNetworkFramework.m \
	Source/DHSpoof.m \
	Source/DHHTTPServer.m \
	Source/DHWebConsole.m \
	Source/DHImageInventory.m \
	Source/DHDisassembler.m \
	Source/DHAnalysis.m \
	Source/DHFileBrowser.m \
	Source/DHZipWriter.m \
	Source/DHDump.m \
	Vendor/fishhook/fishhook.c \
	Vendor/capstone/cs.c \
	Vendor/capstone/Mapping.c \
	Vendor/capstone/MCInst.c \
	Vendor/capstone/MCInstrDesc.c \
	Vendor/capstone/MCRegisterInfo.c \
	Vendor/capstone/SStream.c \
	Vendor/capstone/utils.c \
	$(wildcard Vendor/capstone/arch/AArch64/*.c) \
	$(wildcard Vendor/capstone/arch/ARM/*.c)

decrypt_helper_CFLAGS = -IHeaders -IVendor/fishhook -IVendor/capstone -IVendor/capstone/include \
	-DCAPSTONE_HAS_ARM -DCAPSTONE_HAS_ARM64 -Wno-deprecated-declarations
decrypt_helper_OBJCFLAGS = -fobjc-arc
decrypt_helper_FRAMEWORKS = Foundation UIKit Security WebKit Network
decrypt_helper_INSTALL_PATH = /usr/lib/IOSDecryptHub
ifneq ($(THEOS_PACKAGE_SCHEME),roothide)
decrypt_helper_LDFLAGS = -Wl,-install_name,@executable_path/decrypt_helper.dylib
endif

include $(THEOS_MAKE_PATH)/library.mk
