/**
 * @file     ln_drv_ws2811.c
 * @author   BSP Team 
 * @brief 
 * @version  0.0.0.1
 * @date     2024-05-07
 * 
 * @copyright Copyright (c) 2024 Shanghai Lightning Semiconductor Technology Co. Ltd
 * 
 */

#include "ln_drv_ws2811.h"

void ln_drv_ws2811_send_data(unsigned char *send_data,unsigned int data_len)
{
    //配置DMA传输参数。
    hal_dma_set_mem_addr(DMA_CH_2,(uint32_t)send_data);
    hal_dma_set_data_num(DMA_CH_2,data_len);
    
    //开始传输。
    hal_dma_en(DMA_CH_2,HAL_ENABLE);
    
    //等待传输完成。
    while( hal_dma_get_data_num(DMA_CH_2) != 0);
    
    //发送完成后及时关闭DMA，为下次配置DMA参数做准备。
    hal_dma_en(DMA_CH_2,HAL_DISABLE);
}

void ln_drv_ws2811_init(gpio_port_t port,gpio_pin_t pin)
{
    // 1. 配置WS2811引脚复用
    uint32_t gpio_base = 0;
    if(port == GPIO_A)
        gpio_base = GPIOA_BASE;
    else if(port == GPIO_B)
        gpio_base = GPIOB_BASE;

    hal_gpio_pin_afio_select(gpio_base,pin,WS2811_OUT);
    hal_gpio_pin_afio_en(gpio_base,pin,HAL_ENABLE);
    
    // 2. 初始化WS2811配置
    ws2811_init_t_def ws2811_init;
    
    ws2811_init.br = 16;                                //baud rate = (br+1)*5 * (1 / pclk)
    hal_ws2811_init(WS2811_BASE,&ws2811_init);          //初始化WS2811
    
    hal_ws2811_en(WS2811_BASE,HAL_ENABLE);              //使能WS2811
    hal_ws2811_dma_en(WS2811_BASE,HAL_ENABLE);          //使能WS2811 DMA
    
    //hal_ws2811_it_cfg(WS2811_BASE,WS2811_IT_EMPTY_FLAG,HAL_ENABLE); //配置WS2811中断
    
    // NVIC_EnableIRQ(WS2811_IRQn);                        //使能WS2811中断
    // NVIC_SetPriority(WS2811_IRQn,     1);               //设置WS2811中断优先级
    
    // 3. 配置DMA
    dma_init_t_def dma_init;    
    memset(&dma_init,0,sizeof(dma_init));

    dma_init.dma_mem_addr = (uint32_t)0;                //配置内存地址
    dma_init.dma_data_num = 0;                          //设置传输数量
    dma_init.dma_dir = DMA_READ_FORM_MEM;               //设置传输方向
    dma_init.dma_mem_inc_en = DMA_MEM_INC_EN;           //使之内存是否自增
    dma_init.dma_p_addr = WS2811_DATA_REG;              //设置外设地址
    
    hal_dma_init(DMA_CH_2,&dma_init);                   //DMA初始化
    hal_dma_en(DMA_CH_2,HAL_DISABLE);                   //使能DMA
}

