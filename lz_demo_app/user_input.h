// Copyright(c) 2023 Fraunhofer AISEC

#pragma once

void process_user_input(uint8_t *buf, uint32_t len, bool available);

void user_input_task(void *params);

uint32_t get_interval(void);
