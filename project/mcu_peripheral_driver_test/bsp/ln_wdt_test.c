/**
 * @file     ln_wdt_test.c
 * @author   BSP Team 
 * @brief 
 * @version  0.0.0.1
 * @date     2021-08-24
 * 
 * @copyright Copyright (c) 2021 Shanghai Lightning Semiconductor Technology Co. Ltd
 * 
 */

/*
        WDT Instructions:
                    1. The WDT uses a separate 32k clock.
                    2. Set the WDT running mode to determine whether the WDT generates an interrupt. 0: Counter overflow resets directly; 1: Counter overflow generates an interrupt first, and if it overflows again, it resets.
                    3. Feed time = 2^(8 + TOP) * (1/32k);

*/


#include "ln_wdt_test.h"
#include "hal/hal_wdt.h"
#include "hal/hal_gpio.h"
#include "utils/debug/log.h"


void ln_wdt_test(void)
{
    /* Pin initialization */
    gpio_init_t_def gpio_init;
	memset(&gpio_init,0,sizeof(gpio_init));
    gpio_init.dir = GPIO_OUTPUT;
    gpio_init.pin = GPIO_PIN_5;
    gpio_init.speed = GPIO_HIGH_SPEED;
    hal_gpio_init(GPIOB_BASE,&gpio_init);
    hal_gpio_pin_reset(GPIOB_BASE,GPIO_PIN_5);
    
    /* Watchdog initialization */
    wdt_init_t_def wdt_init;
    memset(&wdt_init,0,sizeof(wdt_init));
    wdt_init.wdt_rmod = WDT_RMOD_1;         // When equal to 0, the counter is reset directly when it overflows; when equal to 1, an interrupt is generated first when the counter overflows, and if it overflows again, it resets.
    wdt_init.wdt_rpl = WDT_RPL_32_PCLK;     // Set the reset delay time
    wdt_init.top = WDT_TOP_VALUE_1;         // Set the value of the watchdog counter. When TOP=1, the corresponding value of the counter is 0x1FF, and the watchdog uses a separate 32k clock,
                                            // so the feeding time must be within (1/32k) * 0x1FF.
    hal_wdt_init(WDT_BASE,&wdt_init);
    
    /* Configure watchdog interrupt */
    NVIC_SetPriority(WDT_IRQn,     4);
    NVIC_EnableIRQ(WDT_IRQn);
    
    /* Enable watchdog */
    hal_wdt_en(WDT_BASE,HAL_ENABLE);
    
    /* Feed the dog first */
    hal_wdt_cnt_restart(WDT_BASE);
    
    /* Test pin */
    hal_gpio_pin_set(GPIOB_BASE,GPIO_PIN_5);
    while(1)
    {
        
    }
}

void WDT_IRQHandler()
{
    // Note: The register clock of WDT uses 32K, while the CPU clock is 160M, much higher than 32K, so it may happen that after clearing the WDT interrupt flag, it enters the WDT interrupt again (WDT 32k operation register is relatively slow).
    hal_wdt_cnt_restart(WDT_BASE);              // Feed dog operation
    hal_gpio_pin_toggle(GPIOB_BASE,GPIO_PIN_5);     // Test pin toggle
    LOG(LOG_LVL_INFO,"feed dog~! \r\n");        // LOG print
}
