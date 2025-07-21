/**
 * @file     main.c
 * @author   BSP Team 
 * @brief    
 * @version  0.0.0.1
 * @date     2021-08-05
 * 
 * @copyright Copyright (c) 2021 Shanghai Lightning Semiconductor Technology Co. Ltd
 * 
 */

#include "hal/hal_common.h"
#include "hal/hal_gpio.h"
#include "ln_test_common.h"
#include "ln_show_reg.h"
#include "utils/debug/log.h"

#include "ln_drv_adc.h"


int main (int argc, char* argv[])
{  
    /****************** 1. 系统初始化 ***********************/
    SetSysClock();
    log_init();   
    LOG(LOG_LVL_INFO,"ln882H init! \n");
    ln_show_reg_init();

    /****************** 2. 外设配置 ***********************/
    /**
        GPIOA0  ->  ADC2
        GPIOA1  ->  ADC3
        GPIOA4  ->  ADC4
        GPIOB3  ->  ADC5
        GPIOB4  ->  ADC6
        GPIOB5  ->  ADC7
     */
    adc_init(ADC_CH5);
    adc_start();
    while(1)
    {
        LOG(LOG_LVL_INFO,"ln882H running! \n");
        
        LOG(LOG_LVL_INFO,"ADC = %d \n",adc_get_data(ADC_CH5));
        
        ln_delay_ms(1000);
    }
}
