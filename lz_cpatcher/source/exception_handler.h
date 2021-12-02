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

#ifndef EXCEPTION_HANDLER_H_
#define EXCEPTION_HANDLER_H_

#define SVC_WDG_IRQ_DISABLE 1
#define SVC_WDG_IRQ_ENABLE 2
#define SVC_SYSTEM_RESET 3

#define svc_disable_wdg_irq() __asm volatile("svc %0 \n" ::"i"(SVC_WDG_IRQ_DISABLE) : "memory")
#define svc_enable_wdg_irq() __asm volatile("svc %0 \n" ::"i"(SVC_WDG_IRQ_ENABLE) : "memory")
#define svc_reset_system() __asm volatile("svc %0 \n" ::"i"(SVC_SYSTEM_RESET) : "memory")

#endif /* EXCEPTION_HANDLER_H_ */
