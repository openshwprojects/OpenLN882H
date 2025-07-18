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

#include "ln_drv_dma.h"

uint8_t data_1[100] = "Shanghai Lightning Semiconductor Technology Co. Ltd";
uint8_t data_2[100];


int main (int argc, char* argv[])
{  
    /****************** 1. 系统初始化 ***********************/
    SetSysClock();
    log_init();   
    LOG(LOG_LVL_INFO,"ln882H init! \n");
    ln_show_reg_init();

    /****************** 2. DMA拷贝测试***********************/
    dma_init();
    dma_mem_cpy(data_2,data_1,strlen((const char*)data_1));

    LOG(LOG_LVL_INFO,"data_1: %s \r\n",data_1);
    LOG(LOG_LVL_INFO,"data_2: %s \r\n",data_2);

    while(1)
    {
        LOG(LOG_LVL_INFO,"ln882H running! \n");
        
        ln_delay_ms(100);
    }
}
