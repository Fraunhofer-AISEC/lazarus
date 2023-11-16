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

PROTO-DEFINITIONS=hub-device-protocol
PROTO-PATHS := $(shell find $(PROTO-DEFINITIONS) -name '*.proto' )
PROTO-FILES := $(notdir $(PROTO-PATHS))
PYTHON-DIR := ../../lz_hub/protobuf
PROTO-C-FILES := $(PROTO-FILES:%.proto=%.pb-c.c)
PROTO-H-FILES := $(PROTO-FILES:%.proto=%.pb-c.h)
PYTHON-FILES := $(PROTO-FILES:%.proto=$(PYTHON-DIR)/%_pb2.py)

GENERATED-FILES = $(PROTO-C-FILES) $(PROTO-H-FILES) $(PYTHON-FILES)

.PHONY: all clean generate-protobuf-sources

all: generate-protobuf-sources

clean:
	rm -f $(GENERATED-FILES)

generate-protobuf-sources: $(GENERATED-FILES)

%.pb-c.h %.pb-c.c &: $(PROTO-DEFINITIONS)/%.proto
	protoc-c --proto_path=$(dir $<) --c_out=. $<

$(PYTHON-DIR)/%_pb2.py: $(PROTO-DEFINITIONS)/%.proto
	protoc --proto_path=$(dir $<) --python_out=$(PYTHON-DIR) $<
