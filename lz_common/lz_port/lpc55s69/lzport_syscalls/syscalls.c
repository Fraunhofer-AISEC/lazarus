/*
 * Copyright(c) 2021 Fraunhofer AISEC
 * Fraunhofer-Gesellschaft zur Foerderung der angewandten Forschung e.V.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "fsl_common.h"
#include "fsl_usart.h"

#include <stdio.h>
#include <sys/stat.h>
#include <sys/errno.h>

#include "lz_config.h"
#include "lzport_usart/lzport_usart.h"
#include "lzport_debug_output/lzport_debug_output.h"

/* Variables */
#undef errno
extern int32_t errno;

uint8_t *__env[1] = { 0 };
uint8_t **environ = __env;

#define WIFI_FILE_NUM 4
#define STDOUT_FILE_NUM 1

int _write(int32_t file, uint8_t *ptr, int32_t len)
{
	if (file == WIFI_FILE_NUM) {
		for (uint32_t i = 0; i < len; i++) {
			lzport_usart_buffer_write(&lzport_usart_tx_fifo_esp, *ptr & (uint16_t)0x01FF);
			USART_EnableInterrupts(ESP_USART, kUSART_TxLevelInterruptEnable);
			ptr++;
		}
		return len;
	} else if (file == STDOUT_FILE_NUM) {
		dbgprint(DBG_ERR, "\nError: printf etc. cannot be used. use 'dbgprint' instead\n");
		return len;
	}
	errno = ENOSYS;
	return -1;
}

int _close(int32_t file)
{
	if (file == WIFI_FILE_NUM) {
		USART_Deinit(ESP_USART);
		return 0;
	}

	errno = ENOSYS;
	return -1;
}

int _fstat(int32_t file, struct stat *st)
{
	if (file == WIFI_FILE_NUM) {
		st->st_mode = S_IFCHR;
		st->st_size = 0;
		return 0;
	}
	errno = ENOSYS;
	return -1;
}

int _isatty(int32_t file)
{
	if (file == WIFI_FILE_NUM) {
		return 1;
	}
	errno = ENOSYS;
	return 0;
}

int _lseek(int32_t file, int32_t ptr, int32_t dir)
{
	if (file == WIFI_FILE_NUM) {
		return 0;
	}
	errno = ENOSYS;
	return -1;
}

int _read(int32_t file, uint8_t *ptr, int32_t len)
{
	errno = ENOSYS;
	return -1;
}

int _readlink(const char *path, char *buf, size_t bufsize)
{
	errno = ENOSYS;
	return -1;
}

int _open(const uint8_t *path, int32_t flags, int32_t mode)
{
	if (strcmp((char *)path, "wifi") == 0) {
		if ((flags == 0) || (flags == 0x10000)) {
			return WIFI_FILE_NUM;
		} else if ((flags == 0x601) || (flags == 0x10601)) {
			return WIFI_FILE_NUM;
		}
	}
	errno = ENOSYS;
	return -1;
}

int _wait(int32_t *status)
{
	errno = ENOSYS;
	return -1;
}

int _unlink(const uint8_t *name)
{
	errno = ENOSYS;
	return -1;
}

int _times(struct tms *buf)
{
	errno = ENOSYS;
	return -1;
}

int _stat(const uint8_t *file, struct stat *st)
{
	errno = ENOSYS;
	return -1;
}

int _symlink(const char *path1, const char *path2)
{
	errno = ENOSYS;
	return -1;
}

int _link(const uint8_t *old, const uint8_t *new)
{
	errno = ENOSYS;
	return -1;
}

int _fork(void)
{
	errno = ENOSYS;
	return -1;
}

int _execve(const uint8_t *name, uint8_t *const *argv, uint8_t *const *env)
{
	errno = ENOSYS;
	return -1;
}

int _exit(void)
{
	errno = ENOSYS;
	return -1;
}

int _kill(void)
{
	errno = ENOSYS;
	return -1;
}

int _getpid(void)
{
	errno = ENOSYS;
	return -1;
}
