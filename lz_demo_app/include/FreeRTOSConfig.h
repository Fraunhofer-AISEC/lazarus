#ifndef _CONF_FREERTOS_H
#define _CONF_FREERTOS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "LPC55S69_cm33_core0.h"
#include "lz_config.h"

/*################# PUBLIC CONSTANTS, VARIABLES & DATA TYPES ##################*/

/* General definitions */
#define configUSE_PREEMPTION 1
#define configUSE_PORT_OPTIMISED_TASK_SELECTION 0
#define configUSE_IDLE_HOOK 0
#define configUSE_TICK_HOOK 0
#define configCPU_CLOCK_HZ SystemCoreClock
#define configTICK_RATE_HZ ((portTickType)1000)
#define configMAX_PRIORITIES 8
#define configMINIMAL_STACK_SIZE 180
#define configTOTAL_HEAP_SIZE ((size_t)(40000))
#define configMAX_TASK_NAME_LEN 25
#define configEXPECTED_IDLE_TIME_BEFORE_SLEEP 10
#define configRUN_FREERTOS_SECURE_ONLY 0
#define configENABLE_TRUSTZONE 0
#define configENABLE_FPU 1
#define configENABLE_MPU 0

#if (1 == FREERTOS_BENCHMARK_ACTIVE)
#define configUSE_TRACE_FACILITY 1
#define configUSE_STATS_FORMATTING_FUNCTIONS 1
#define configGENERATE_RUN_TIME_STATS 1
extern void freertos_benchmark_init_ticks(void);
extern uint32_t freertos_benchmark_get_ticks(void);
#define portCONFIGURE_TIMER_FOR_RUN_TIME_STATS() (freertos_benchmark_init_ticks())
#define portGET_RUN_TIME_COUNTER_VALUE() (freertos_benchmark_get_ticks())
#else
#define configUSE_TRACE_FACILITY 0
#define configUSE_STATS_FORMATTING_FUNCTIONS 0
#define configGENERATE_RUN_TIME_STATS 0
#endif

#define configUSE_16_BIT_TICKS 0
#define configIDLE_SHOULD_YIELD 1
#define configUSE_MUTEXES 1
#define configQUEUE_REGISTRY_SIZE 8
#define configCHECK_FOR_STACK_OVERFLOW 0
#define configUSE_RECURSIVE_MUTEXES 1
#define configUSE_MALLOC_FAILED_HOOK 0
#define configUSE_APPLICATION_TASK_TAG 0
#define configUSE_COUNTING_SEMAPHORES 1
#define configUSE_TICKLESS_IDLE 0
#define configUSE_QUEUE_SETS 0

/* Co-routine definitions. */
#define configUSE_CO_ROUTINES 0
#define configMAX_CO_ROUTINE_PRIORITIES (2)

/* Software timer definitions. */
#define configUSE_TIMERS 0
#define configTIMER_TASK_PRIORITY (configMAX_PRIORITIES - 1)
#define configTIMER_QUEUE_LENGTH 5
#define configTIMER_TASK_STACK_DEPTH (configMINIMAL_STACK_SIZE * 2)

/* Set the following definitions to 1 to include the API function, or zero
to exclude the API function. */
#define INCLUDE_vTaskPrioritySet 1
#define INCLUDE_uxTaskPriorityGet 1
#define INCLUDE_vTaskDelete 1
#define INCLUDE_vTaskCleanUpResources 1
#define INCLUDE_vTaskSuspend 1
#define INCLUDE_vTaskDelayUntil 1
#define INCLUDE_vTaskDelay 1
#define INCLUDE_eTaskStateGet 1
#define INCLUDE_uxTaskGetStackHighWaterMark 1
#define INCLUDE_xTaskGetSchedulerState 1
#define INCLUDE_xTaskGetIdleTaskHandle 1

/* FreeRTOS+CLI definitions. */

/* Dimensions a buffer into which command outputs can be written.  The buffer
can be declared in the CLI code itself, to allow multiple command consoles to
share the same buffer.  For example, an application may allow access to the
command interpreter by UART and by Ethernet.  Sharing a buffer is done purely
to save RAM.  Note, however, that the command console itself is not re-entrant,
so only one command interpreter interface can be used at any one time.  For
that reason, no attempt at providing mutual exclusion to the buffer is
attempted. */
#define configCOMMAND_INT_MAX_OUTPUT_SIZE 400

/* Cortex-M specific definitions. */
#ifdef __NVIC_PRIO_BITS
/* __BVIC_PRIO_BITS will be specified when CMSIS is being used. */
#define configPRIO_BITS __NVIC_PRIO_BITS
#else
#define configPRIO_BITS 4 /* 15 priority levels */
#endif

/* The lowest interrupt priority that can be used in a call to a "set priority"
function. */
#define configLIBRARY_LOWEST_INTERRUPT_PRIORITY 0x0f

/* The highest interrupt priority that can be used by any interrupt service
routine that makes calls to interrupt safe FreeRTOS API functions.  DO NOT CALL
INTERRUPT SAFE FREERTOS API FUNCTIONS FROM ANY INTERRUPT THAT HAS A HIGHER
PRIORITY THAN THIS! (higher priorities are lower numeric values. */
#define configLIBRARY_MAX_SYSCALL_INTERRUPT_PRIORITY 10

/* Interrupt priorities used by the kernel port layer itself.  These are generic
to all Cortex-M ports, and do not rely on any particular library functions. */
#define configKERNEL_INTERRUPT_PRIORITY                                                            \
	(configLIBRARY_LOWEST_INTERRUPT_PRIORITY << (8 - configPRIO_BITS))
#define configMAX_SYSCALL_INTERRUPT_PRIORITY                                                       \
	(configLIBRARY_MAX_SYSCALL_INTERRUPT_PRIORITY << (8 - configPRIO_BITS))

/* Assert in case of FreeRTOS errors */
extern void freertos_assert_called(const char *file, uint32_t line);
#define configASSERT(x)                                                                            \
	if ((x) == 0) {                                                                                \
		freertos_assert_called(__FILE__, __LINE__);                                                \
	}

/* Definitions that map the FreeRTOS port interrupt handlers to their CMSIS standard names. */
#define vPortSVCHandler SVC_Handler
#define xPortPendSVHandler PendSV_Handler
#define xPortSysTickHandler SysTick_Handler

/* Activate trace recorder */
#if defined(__GNUC__)
#if (configUSE_TRACE_FACILITY == 1)
#include "trcRecorder.h"
#endif
#endif

#ifdef __cplusplus
}
#endif

#endif /* _CONF_FREERTOS_H */
