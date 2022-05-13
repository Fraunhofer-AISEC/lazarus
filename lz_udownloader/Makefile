# Copyright(c) 2021 Fraunhofer AISEC
# Fraunhofer-Gesellschaft zur Foerderung der angewandten Forschung e.V.
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the License); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an AS IS BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

PROJECT_NAME = lz_udownloader

# The build directory. If you want to change the build directory, you also need
# to adjust the provisioning scripts.
BUILD_DIR := ./build

# All source directories
SRC_DIRS := ./ \
			../thirdparty/lpc55s69_sdk/device \
			../thirdparty/lpc55s69_sdk/drivers \
			../thirdparty/lpc55s69_sdk/component \
			../thirdparty/lpc55s69_sdk/utilities \
			../thirdparty/mbedtls/library \
			../lz_common/lz_common \
			../lz_common/lz_crypto \
			../lz_common/lz_net \
			../port/lpc55s69/lz_udownloader/board_init \
			../port/lpc55s69/peripherals/lzport_gpio \
			../port/lpc55s69/peripherals/lzport_debug_output \
			../port/lpc55s69/peripherals/lzport_flash \
			../port/lpc55s69/peripherals/lzport_memory \
			../port/lpc55s69/peripherals/lzport_rng \
			../port/lpc55s69/peripherals/lzport_usart \
			../port/lpc55s69/peripherals/lzport_net \
			../port/lpc55s69/peripherals/lzport_systick_delay \
			../port/lpc55s69/peripherals/lzport_syscalls \



EXCLUDE_DIRS :=

# All include directories
INCLUDES = 	./ \
			../lz_common \
			../lz_common/lz_common \
			../lz_common/lz_crypto \
			../lz_common/lz_net \
			../lz_common/lz_trustzone_handler \
			../thirdparty/mbedtls/include \
			../thirdparty/mbedtls/port/ksdk \
			../thirdparty/mbedtls/library \
			../thirdparty/lpc55s69_sdk/drivers \
			../thirdparty/CMSIS \
			../thirdparty/lpc55s69_sdk/device \
			../thirdparty/lpc55s69_sdk/utilities \
			../thirdparty/lpc55s69_sdk/component/serial_manager \
			../thirdparty/lpc55s69_sdk/component/lists \
			../thirdparty/lpc55s69_sdk/component/uart \
			../port/lpc55s69/peripherals/lzport_memory \
			../port/lpc55s69/peripherals/lzport_debug_output \
			../port/lpc55s69/peripherals/lzport_rng \
			../port/lpc55s69/peripherals/lzport_gpio \
			../port/lpc55s69/peripherals/lzport_net \
			../port/lpc55s69/peripherals/lzport_systick_delay \
			../port/lpc55s69/peripherals/lzport_usart \
			../port/lpc55s69/lz_udownloader/board_init \


# Defines used in that build
DEFINES = CPU_LPC55S69JBD100 \
			CPU_LPC55S69JBD100_cm33 \
			CPU_LPC55S69JBD100_cm33_core0 \
			FSL_RTOS_BM \
			SDK_OS_BAREMETAL \
			SDK_DEBUGCONSOLE=1 \
			CR_INTEGER_PRINTF \
			PRINTF_FLOAT_ENABLE=0 \
			__MCUXPRESSO \
			__USE_CMSIS \
			DEBUG \
			__MULTICORE_MASTER \
			MBEDTLS_CONFIG_FILE='"ksdk_mbedtls_config.h"' \
			__NEWLIB__ \
			SERIAL_PORT_TYPE_UART=1

# Optimization
CFLAGS = -O1

# Warning level
CFLAGS += -Wall

# Needed for trustzone secure projects (lz_udownloader is non-secure)
# CFLAGS += -mcmse

# Other compiler flags that are needed
CFLAGS += -c -fno-common -g3 -ffunction-sections -fdata-sections -ffreestanding -fno-builtin -mcpu=cortex-m33 -mfpu=fpv5-sp-d16 -mfloat-abi=hard -mthumb -fstack-usage -fmacro-prefix-map="../utilities/"=. -specs=nano.specs -MMD -MP

# Used c-compiler
CC = arm-none-eabi-gcc

# External libraries
LIBS = ./libs

# Linkerflags
LDFLAGS += -nostdlib -mcpu=cortex-m33 -mfpu=fpv5-sp-d16 -mfloat-abi=hard -mthumb -T ./linker_script_$(PROJECT_NAME).ld
LDFLAGS += -Xlinker --gc-sections -Xlinker -print-memory-usage -Xlinker --sort-section=alignment -Xlinker --cref -Xlinker -Map="$(BUILD_DIR)/$(PROJECT_NAME).map" -o "$(BUILD_DIR)/$(PROJECT_NAME).axf"
LDFLAGS += ../lz_core/build/lz_core_CMSE_lib.o

# Name of the file with a build number
BUILD_NO_FILE := build_no

###############################################################################
######################### Do not edit below this line #########################
###############################################################################

# Automatically finds all source files in the specified source directories
EXCLUDE-DIRS := $(addsuffix /%,$(EXCLUDE_DIRS))
SRC-FILES-TMP := $(shell find $(SRC_DIRS) -name '*.c' )
SRC-FILES := $(filter-out $(filter $(EXCLUDE-DIRS),$(SRC-FILES-TMP)),$(SRC-FILES-TMP))

# Generates .o files based on the found source files (adding $(PROJECT_NAME),
# to have $(PROJECT_NAME) and lz_common object files in the build folder)
OBJ-FILES := $(SRC-FILES:%.c=$(BUILD_DIR)/$(PROJECT_NAME)/%.o)

# Generates .d (dependency) files based on the found source files
DEP-FILES := $(OBJ-FILES:.o=.d)

# Adds the libraries to the linking flags
LDFLAGS += $(addprefix -L,$(LIBS))

# Adds the defines to the CFLAGS
CFLAGS += $(addprefix -D,$(DEFINES))

# Adds the -I prefix to the includes
INCLUDE-DIRS = $(addprefix -I,$(INCLUDES))

# Default target
all: post-build

compile: $(OBJ-FILES)

link: compile
	@echo 'Linking binary ...'
	$(CC) $(OBJ-FILES) $(LDFLAGS)
	@echo 'Linking done'

post-build: link increase_build_no
	@echo 'Post build ...'
	-arm-none-eabi-size "$(BUILD_DIR)/$(PROJECT_NAME).axf" ; arm-none-eabi-objcopy -v -O binary "$(BUILD_DIR)/$(PROJECT_NAME).axf" "$(BUILD_DIR)/$(PROJECT_NAME).bin" && python3 ../lz_hub/lz_sign_binary.py "$(BUILD_DIR)/$(PROJECT_NAME)".bin $(BUILD_NO_FILE) "$(BUILD_DIR)/$(PROJECT_NAME)"_signed.bin ../lz_hub/certificates/
	@echo 'Post build done'

# Increases the build number in the corresponding file
increase_build_no: generate_build_no
	@$(eval VERSION := $$(shell cat $(BUILD_NO_FILE)))
	@echo $$(($(VERSION) + 1)) > $(BUILD_NO_FILE)

# Generates the build number file
generate_build_no:
	@if ! test -f $(BUILD_NO_FILE); then echo 0 > $(BUILD_NO_FILE); fi

# Describes how an .o file should be generated (adding $(PROJECT_NAME), to have
# $(PROJECT_NAME) and lz_common object files in the build folder)
$(BUILD_DIR)/$(PROJECT_NAME)/%.o: %.c
	mkdir -p $(dir $@)
	@echo 'Building file: $<'
	$(CC) $(CFLAGS) $(INCLUDE-DIRS) -c $< -o $@
	@echo 'Finished building: $<'

# Phony rule
.Phony: all compile link post-build increase_build_no generate_build_no clean

# Cleans up project
clean:
	rm -rf $(BUILD_DIR)

# Includes all dependency files, so if a header is changes, the corresponding
# files will be rebuilt
-include $(DEP-FILES)
