#include "ln882h.h"

#define CFG_USING_CM_BACKTRACE

#ifdef CFG_USING_CM_BACKTRACE
#include "utils/debug/CmBackTrace/cm_backtrace.h"
#endif /* CFG_USING_CM_BACKTRACE */

#include <stdbool.h>
#include "hal/hal_common.h"
#include "hal/hal_interrupt.h"

void set_interrupt_priority(void)
{
    NVIC_SetPriorityGrouping(4);

    NVIC_SetPriority(SysTick_IRQn,   (1<<__NVIC_PRIO_BITS) - 1);
    NVIC_SetPriority(PendSV_IRQn,    (1<<__NVIC_PRIO_BITS) - 1);

    NVIC_SetPriority(WDT_IRQn,       4);
    NVIC_SetPriority(EXT_IRQn,       4);
    NVIC_SetPriority(RTC_IRQn,       4);
    NVIC_SetPriority(RFSLP_IRQn,     4);
    NVIC_SetPriority(MAC_IRQn,       2);

    NVIC_SetPriority(BLE_WAKE_IRQn,  4);
    NVIC_SetPriority(BLE_ERR_IRQn,   4);
    NVIC_SetPriority(BLE_MAC_IRQn,   1);
    NVIC_SetPriority(DMA_IRQn,       4);
    NVIC_SetPriority(QSPI_IRQn,      4);

    NVIC_SetPriority(SDIO_1_IRQn,    4);
    NVIC_SetPriority(SDIO_2_IRQn,    4);
    NVIC_SetPriority(SDIO_3_IRQn,    4);

    NVIC_SetPriority(FPIXC_IRQn,     4);
    NVIC_SetPriority(FPOFC_IRQn,     4);
    NVIC_SetPriority(FPUFC_IRQn,     4);
    NVIC_SetPriority(FPIOC_IRQn,     4);
    NVIC_SetPriority(FPDZC_IRQn,     4);
    NVIC_SetPriority(FPIDC_IRQn,     4);

    NVIC_SetPriority(I2C_IRQn,       4);
    NVIC_SetPriority(SPI0_IRQn,      4);
    NVIC_SetPriority(SPI1_IRQn,      4);

    NVIC_SetPriority(UART0_IRQn,     4);
    NVIC_SetPriority(UART1_IRQn,     2);
    NVIC_SetPriority(UART2_IRQn,     2);

    NVIC_SetPriority(ADC_IRQn,       4);
    NVIC_SetPriority(WS2811_IRQn,    4);
    NVIC_SetPriority(I2S_IRQn,       4);

    NVIC_SetPriority(GPIOA_IRQn,     4);
    NVIC_SetPriority(GPIOB_IRQn,     4);

    NVIC_SetPriority(TIMER0_IRQn,    4);
    NVIC_SetPriority(TIMER1_IRQn,    4);
    NVIC_SetPriority(TIMER2_IRQn,    4);
    NVIC_SetPriority(TIMER3_IRQn,    4);
    NVIC_SetPriority(ADV_TIMER_IRQn, 4);

    NVIC_SetPriority(AES_IRQn,       4);
    NVIC_SetPriority(TRNG_IRQn,      4);
    NVIC_SetPriority(PAOTD_IRQn,     2);
}

void switch_global_interrupt(hal_en_t enable)
{
    if(enable)
        __enable_irq();
    else
        __disable_irq();
}

#if (defined(__CC_ARM) && (__ARMCC_VERSION < 6000000)) /* ARMCC5 */
    __asm void fault_handler(void)
    {
        #ifdef CFG_USING_CM_BACKTRACE
        IMPORT  cm_backtrace_fault
        #endif
     
        MOV    R0, LR
        MOV    R1, SP
        #ifdef CFG_USING_CM_BACKTRACE
        BL     __cpp(cm_backtrace_fault)
        #endif
        B      .
    }
#elif (defined(__GNUC__) && !defined(__ARMCC_VERSION)) || (defined(__ARMCC_VERSION) && (__ARMCC_VERSION >= 6010050)) /* GCC or ARMCC6 */
    static inline void fault_handler(void)
    {
        __asm__ volatile(
        "MOV    R0, LR;"
        "MOV    R1, SP;"
        #ifdef CFG_USING_CM_BACKTRACE
        "BL     cm_backtrace_fault;"
        #endif
        "B   .");
    }
#else
    #error "Unsupported compiler!!!"
#endif

void NMI_Handler (void) {
    fault_handler();
}

void HardFault_Handler (void) {
    fault_handler();
}

void MemManage_Handler (void) {
    fault_handler();
}

void BusFault_Handler (void) {
    fault_handler();
}

void UsageFault_Handler (void) {
    fault_handler();
}

void DebugMon_Handler (void) {
    fault_handler();
}


/**********************************************************************************************************/
/*       if ARMCC MicroLib disable                                                                        */
/* User code templates for system I/O function retargeting                                                */
/* Reference: https://www.keil.com/pack/doc/compiler/RetargetIO/html/Retarget_Overview.html#autotoc_md0   */
/**********************************************************************************************************/
#if ((!defined(__MICROLIB)) && defined(__ARMCC_VERSION))

  #if (defined(__ARMCC_VERSION) && (__ARMCC_VERSION >= 6010050)) /* ARMCC6 */
    __ASM (".global __use_no_semihosting");      
  #elif (defined(__CC_ARM) && (__ARMCC_VERSION < 6000000)) /* ARMCC5 */
    #pragma import(__use_no_semihosting)             
    struct __FILE 
    { 
        int handle; 
    }; 
  #endif

  __asm(".global __ARM_use_no_argv\n\t");
  
  #include <rt_sys.h>
  
  FILEHANDLE _sys_open(const char * name, int openmode) {
      return 0;  
  }
  void _ttywrch(int ch) {
      ch = ch;
  }
  void _sys_exit(int x) { 
  	x = x; 
  } 
  
  int fputc(int ch, FILE *f) { 
      //TODO: uart send ch
  	return ch;
  }
  
  int _sys_close(FILEHANDLE fh) {
      return 0; //return success
  }
  int _sys_write(FILEHANDLE fh, const unsigned char * buf, unsigned len, int mode) {
      return 0;   
  }
  int _sys_read(FILEHANDLE fh, unsigned char * buf, unsigned len, int mode) {
      return 0;       
  }
  
  int _sys_istty(FILEHANDLE fh) {
      return 1; // no interactive device present
  }
  int _sys_seek(FILEHANDLE fh, long pos) {
      return -1; // error
  }
  int _sys_ensure(FILEHANDLE fh) {
      return 0; // success
  }
  long _sys_flen(FILEHANDLE fh) {
      return 0;
  }
  
  char *_sys_command_string(char *cmd, int len){
      return 0;
  }
#endif 

