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
#include "ln_show_reg.h"
#include "utils/debug/log.h"
#include "ln_test_common.h"
#include "ln_drv_ws2811.h"
#define LED_AMOUNT  50  

static unsigned char led_data_arr[LED_AMOUNT * 3 ] = {0xFF,0x00,0x00,  
                                                      0x00,0xFF,0x00,  
                                                      0x00,0x00,0xFF,
                                                      0xFF,0x00,0x00,
                                                      0x00,0xFF,0x00,
                                                      0x00,0x00,0xFF,
                                                      0xFF,0x00,0x00,
                                                      0x00,0xFF,0x00,
                                                      0x00,0x00,0xFF,
                                                      0xFF,0x00,0x00,
                                                      0x00,0xFF,0x00,
                                                      0x00,0x00,0xFF,
                                                      0xFF,0x00,0x00,
                                                      0x00,0xFF,0x00,
                                                      0x00,0x00,0xFF,
                                                      0xFF,0x00,0x00,
                                                      0x00,0xFF,0x00,
                                                      0x00,0x00,0xFF,
                                                      0xFF,0x00,0x00,
                                                      0x00,0xFF,0x00};
                                                      
static unsigned char led_data_arr1[LED_AMOUNT * 3] = {0x00,0x00,0x00,  
                                                      0x00,0x00,0x00,  
                                                      0x00,0x00,0x00,
                                                      0x00,0x00,0x00,
                                                      0x00,0x00,0x00,
                                                      0x00,0x00,0x00,
                                                      0x00,0x00,0x00,
                                                      0x00,0x00,0x00,
                                                      0x00,0x00,0x00,
                                                      0x00,0x00,0x00,
                                                      0x00,0x00,0x00,
                                                      0x00,0x00,0x00,
                                                      0x00,0x00,0x00,
                                                      0x00,0x00,0x00,
                                                      0x00,0x00,0x00,
                                                      0x00,0x00,0x00,
                                                      0x00,0x00,0x00,
                                                      0x00,0x00,0x00,
                                                      0x00,0x00,0x00,
                                                      0x00,0x00,0x00};

int main (int argc, char* argv[])
{  
    /****************** 1. 系统初始化 ***********************/
    SetSysClock();
    log_init();   
    LOG(LOG_LVL_INFO,"ln882H init! \n");
    ln_show_reg_init();

    /****************** 2. WS2811 测试***********************/
    ln_drv_ws2811_init(GPIO_A,GPIO_PIN_7);

    while(1)
    {
        ln_drv_ws2811_send_data(led_data_arr,3 * 3);                //点亮三盏灯
        ln_delay_ms(500);
        ln_drv_ws2811_send_data(led_data_arr1,LED_AMOUNT * 3);      //熄灭所有灯
        ln_delay_ms(500);
    }
}
