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

#include "hal/hal_clock.h"
#include "hal/hal_common.h"
#include "hal/hal_gpio.h"
#include "hal/hal_timer.h"
#include "ln_show_reg.h"
#include "ln_test_common.h"
#include "utils/debug/log.h"

#include "ln_drv_pwm.h"

int main(int argc, char *argv[])
{
    uint32_t pwm_duty = 0;

    /****************** 1. 系统初始化 ***********************/
    SetSysClock();
    log_init();
    LOG(LOG_LVL_INFO, "ln882H init! \n");
    ln_show_reg_init();

    /****************** 2. 外设配置 ***********************/
    /*
        LN882H一共有6个高级Timer(Timer0~Timer5),每个高级Timer有两个通道PWM(a和b)。
        因此同一Timer的两个通道必须设置成相同的频率，占空比可以不相同。

        同时针对照明应用的客户，会在占空比会0%和100%的时候直接设置GPIO为低电平或者高电平，以防止出现毛刺。

        PWM_CHA_0 = 0,  ->ADV_TIMER_0_BASE
        PWM_CHA_1 = 1,

        PWM_CHA_2 = 2,  ->ADV_TIMER_1_BASE
        PWM_CHA_3 = 3,

        PWM_CHA_4 = 4,  ->ADV_TIMER_2_BASE
        PWM_CHA_5 = 5,

        PWM_CHA_6 = 6,  ->ADV_TIMER_3_BASE
        PWM_CHA_7 = 7,

        PWM_CHA_8 = 8,  ->ADV_TIMER_4_BASE
        PWM_CHA_9 = 9,

        PWM_CHA_10 = 10,->ADV_TIMER_5_BASE
        PWM_CHA_11 = 11,

    */
    /*必须先初始化所有的PWM配置之后才能开始PWM，否则可能会出现异常*/
    pwm_init(10000, 20, PWM_CHA_0, GPIO_B, GPIO_PIN_5); // 初始化PWM,设置频率为10K,占空比为20%
    pwm_init(10000, 20, PWM_CHA_1, GPIO_B, GPIO_PIN_6); // 初始化PWM
    pwm_init(10000, 20, PWM_CHA_2, GPIO_B, GPIO_PIN_7); // 初始化PWM

    pwm_start(PWM_CHA_0);                               // 开始产生PWM
    pwm_start(PWM_CHA_1);                               // 开始产生PWM
    pwm_start(PWM_CHA_2);                               // 开始产生PWM
    while (1)
    {
        pwm_duty++;
        if (pwm_duty > 100){
            pwm_duty = 0;
            pwm_set_freq(PWM_CHA_0,100000);
        }
        pwm_set_duty(PWM_CHA_0,pwm_duty); // 配置占空比
        pwm_set_duty(PWM_CHA_1,pwm_duty);
        pwm_set_duty(PWM_CHA_2,pwm_duty);

        LOG(LOG_LVL_INFO, "ln882H running! \n");

        LOG(LOG_LVL_INFO, "Duty = %f\n", pwm_get_duty(PWM_CHA_0));

        ln_delay_ms(100);
    }
}
