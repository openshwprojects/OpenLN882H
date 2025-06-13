/**
 * @file freertos_common.c
 * @author LightningSemi WLAN Team
 * Copyright (C) 2018 LightningSemi Technology Co., Ltd. All rights reserved.
 */
#include "proj_config.h"
#include "freertos_common.h"

#if defined(__CC_ARM) || (defined(__ARMCC_VERSION) && (__ARMCC_VERSION >= 6010050))
    extern unsigned int Image$$HEAP_SPACE0$$ZI$$Base;
    extern unsigned int Image$$HEAP_SPACE0$$ZI$$Limit;
    #define HEAP0_START                      (&Image$$HEAP_SPACE0$$ZI$$Base)
    #define HEAP0_END                        (&Image$$HEAP_SPACE0$$ZI$$Limit)
	#define HEAP0_LEN                        ((uint8_t *)HEAP0_END - (uint8_t *)HEAP0_START)
#elif __GNUC__
    extern void *heap0_start;
    extern void *heap0_end;
    extern void *heap0_len;
    #define HEAP0_START                      (&heap0_start)
    #define HEAP0_END                        (&heap0_end)
    #define HEAP0_LEN                        (&heap0_len)
#else
    #error "Unknown compiler!!!"
#endif

/* declarations */
static void OS_HeapSizeConfig(void);

static HeapRegion_t xHeapRegions[] = {
    {NULL, 0},
    {NULL, 0}
};

void OS_HeapSizeConfig(void)
{
    xHeapRegions[0].pucStartAddress = (uint8_t *)(HEAP0_START);
    xHeapRegions[0].xSizeInBytes    = (size_t)HEAP0_LEN;

    xHeapRegions[1].pucStartAddress = NULL;
    xHeapRegions[1].xSizeInBytes    = 0;
}

void OS_DefineHeapRegions(void)
{
    OS_HeapSizeConfig();
    vPortDefineHeapRegions(xHeapRegions);
}

int OS_HeapSizeGet(void)
{
    return HEAP0_LEN;
}

#if defined(__CC_ARM)
void *$Sub$$malloc(size_t size)
{
    return OS_Malloc(size);
}

void *$Sub$$realloc(void *mem, size_t newsize)
{
    return OS_Realloc(mem, newsize);
}

void $Sub$$free(void *addr)
{
    OS_Free(addr);
}
#endif
