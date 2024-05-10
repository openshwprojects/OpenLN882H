/**
 * @file     ln_drv_ws2811.h
 * @author   BSP Team 
 * @brief 
 * @version  0.0.0.1
 * @date     2024-05-07
 * 
 * @copyright Copyright (c) 2024 Shanghai Lightning Semiconductor Technology Co. Ltd
 * 
 */

#ifndef __LN_DRV_WS2811_H
#define __LN_DRV_WS2811_H


#include "hal/hal_ws2811.h"
#include "hal/hal_gpio.h"
#include "hal/hal_dma.h"


typedef enum
{
    GPIO_A = 0,
    GPIO_B = 1,
}gpio_port_t;

void ln_drv_ws2811_send_data(unsigned char *send_data,unsigned int data_len);
void ln_drv_ws2811_init(gpio_port_t port,gpio_pin_t pin);


#endif
