#include "osal/osal.h"
#include "utils/debug/log.h"
#include "utils/debug/ln_assert.h"
#include "utils/system_parameter.h"
#include "utils/ln_psk_calc.h"
#include "utils/power_mgmt/ln_pm.h"
#include "utils/sysparam_factory_setting.h"
#include "wifi.h"
#include "wifi_port.h"
#include "netif/ethernetif.h"
#include "wifi_manager.h"
#include "lwip/tcpip.h"
#include "drv_adc_measure.h"
#include "hal/hal_adc.h"
#include "ln_nvds.h"
#include "ln_wifi_err.h"
#include "ln_misc.h"
#include "ln882h.h"
#include "hal/hal_flash.h"

#include "usr_app.h"
#include "usr_ble_app.h"

static OS_Thread_t g_usr_app_thread;
#define USR_APP_TASK_STACK_SIZE   6*256 //Byte
#define WIFI_TEMP_CALIBRATE             1//1


#if WIFI_TEMP_CALIBRATE
static OS_Thread_t g_temp_cal_thread;
#define TEMP_APP_TASK_STACK_SIZE   4*256 //Byte
#endif

/* declaration */
static void wifi_init_sta(void);
static void usr_app_task_entry(void *params);
static void temp_cal_app_task_entry(void *params);

static uint8_t mac_addr[6]   = {0x00, 0x50, 0xC2, 0x5E, 0xAA, 0xDA};
static uint8_t psk_value[40] = {0x0};

wifi_sta_connect_t connect = {
    .ssid    = "TP-LINK_C0DE",
    .pwd     = "12345678",
    .bssid   = NULL,
    .psk_value = NULL,
};

wifi_scan_cfg_t scan_cfg = {
        .channel   = 0,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time = 20,
};

static uint32_t djb_hash_hexdata(const char *input, uint32_t len)
{
    uint32_t hash = 5381;
    int c = *input;

    for (uint32_t i = 0; i < len; i++)
    {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
        input++;
        c = *input;
    }
    return hash;
}

static void chip_uuid_generate_mac(uint8_t mac[6])
{
    uint8_t chip_uid[16] = {0};
    uint32_t hash = 0;
    hal_flash_read_unique_id(chip_uid);
    hash = djb_hash_hexdata((const char *)chip_uid, sizeof(chip_uid));
    mac[0] = 0x00;
    mac[1] = 0x50;
    mac[2] = (uint8_t)((hash) & 0xFF);
    mac[3] = (uint8_t)((hash >> 8) & 0xFF);
    mac[4] = (uint8_t)((hash >> 16) & 0xFF);
    mac[5] = (uint8_t)((hash >> 24) & 0xFF);
}

static void wifi_scan_complete_cb(void * arg)
{
    LN_UNUSED(arg);

    ln_list_t *list;
    uint8_t node_count = 0;
    ap_info_node_t *pnode;

    wifi_manager_ap_list_update_enable(LN_FALSE);

    // 1.get ap info list.
    wifi_manager_get_ap_list(&list, &node_count);

    // 2.print all ap info in the list.
    LN_LIST_FOR_EACH_ENTRY(pnode, ap_info_node_t, list,list)
    {
        uint8_t * mac = (uint8_t*)pnode->info.bssid;
        ap_info_t *ap_info = &pnode->info;

        LOG(LOG_LVL_INFO, "\tCH=%2d,RSSI= %3d,", ap_info->channel, ap_info->rssi);
        LOG(LOG_LVL_INFO, "BSSID:[%02X:%02X:%02X:%02X:%02X:%02X],SSID:\"%s\"\r\n", \
                           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ap_info->ssid);
    }

    wifi_manager_ap_list_update_enable(LN_TRUE);
}

static void wifi_init_sta(void)
{
    //1. generate mac
    //ln_generate_random_mac(mac_addr);
    chip_uuid_generate_mac(mac_addr);
    sysparam_sta_mac_update((const uint8_t *)mac_addr);

    //2. net device(lwip)
    netdev_set_mac_addr(NETIF_IDX_STA, mac_addr);
    netdev_set_active(NETIF_IDX_STA);
    sysparam_sta_mac_update((const uint8_t *)mac_addr);

    //3. wifi start
    wifi_manager_reg_event_callback(WIFI_MGR_EVENT_STA_SCAN_COMPLETE, &wifi_scan_complete_cb);

    if(WIFI_ERR_NONE != wifi_sta_start(mac_addr, WIFI_NO_POWERSAVE)){
        LOG(LOG_LVL_ERROR, "[%s]wifi sta start filed!!!\r\n", __func__);
    }

    connect.psk_value = NULL;
    if (strlen(connect.pwd) != 0) {
        if (0 == ln_psk_calc(connect.ssid, connect.pwd, psk_value, sizeof (psk_value))) {
            connect.psk_value = psk_value;
            hexdump(LOG_LVL_INFO, "psk value ", psk_value, sizeof(psk_value));
        }
    }

    //4. wifi sta connect
    wifi_sta_connect(&connect, &scan_cfg);
}

#include "mqtt_client.h"
#define MQTT_TOPIC    "/usr_0001/temperature/subscribe"

void mqtt_incoming_pub_callback(char* topic, uint16_t topic_len, char* message, uint16_t message_len)
{
#if 1
    char *message_str = OS_Malloc(message_len + 1);
    if (message_str) {
        strncpy(message_str, message, message_len);
        message_str[message_len] = '\0';
        
        LOG(LOG_LVL_INFO, "incoming message[%s]:%s\r\n", topic, message_str);
        OS_Free(message_str);
    }
#endif
}

static void mqtt_connected_callback(void)
{
    LOG(LOG_LVL_INFO, "mqtt client connected\r\n");
    __mqtt_cli_subscribe(MQTT_TOPIC, 1);
}

static int mqtt_send_count_data(uint32_t count)
{
    char buf[32] = {0};
    snprintf(buf, sizeof(buf), "%u", count);
    __mqtt_cli_publish(MQTT_TOPIC, (const char*)buf, strlen(buf), 0, 0);
}

static void mqtt_disconnected_callback(void)
{
    LOG(LOG_LVL_INFO, "mqtt client disconnected\r\n");
}

mqtt_client_cfg_t  mqttcfg = {
    .hostname  = "broker.emqx.io",
    .port      = 8883,
    .keepalive = 30,

    .client_id = "client_id_usr_0001",
    .username  = "usr_0001",
    .password  = "pwd_0001",

    .server_root_ca_pem = NULL,
    .client_cert_pem    = NULL,
    .client_key_pem     = NULL,

    .last_will_topic_name = NULL,
    .last_will_message    = NULL,

    .is_connected = 0,
    .connected_cb    = mqtt_connected_callback,
    .disconnected_cb = mqtt_disconnected_callback,
    .incoming_pub_cb = mqtt_incoming_pub_callback,
};

static void usr_app_task_entry(void *params)
{
    LN_UNUSED(params);

    wifi_manager_init();
    wifi_init_sta();

    while (!netdev_got_ip()) {
        OS_MsDelay(1000);
    }
    
    creat_mqtt_task(&mqttcfg);
    while (!mqttcfg.is_connected) {
        OS_MsDelay(1000);
    }
    
    while(1)
    {
        OS_MsDelay(1000);
        mqtt_send_count_data(OS_GetTicks());
        OS_MsDelay(1000);
        mqtt_send_count_data(OS_GetTicks());
        
        OS_MsDelay(35000);
    }
}

static void temp_cal_app_task_entry(void *params)
{
    LN_UNUSED(params);

    int8_t cap_comp = 0;
    uint16_t adc_val = 0;
    int16_t curr_adc = 0;
    uint8_t cnt = 0;

    if (NVDS_ERR_OK == ln_nvds_get_xtal_comp_val((uint8_t *)&cap_comp)) {
        if ((uint8_t)cap_comp == 0xFF) {
            cap_comp = 0;
        }
    }

    drv_adc_init();

    wifi_temp_cal_init(drv_adc_read(ADC_CH0), cap_comp);

    while (1)
    {
        OS_MsDelay(1000);

        adc_val = drv_adc_read(ADC_CH0);
        wifi_do_temp_cal_period(adc_val);

        curr_adc = (adc_val & 0xFFF);

        cnt++;
        if ((cnt % 60) == 0) {
            LOG(LOG_LVL_INFO, "adc raw: %4d, temp_IC: %4d\r\n", curr_adc, (int16_t)(25 + (curr_adc - 770) / 2.54f));
            LOG(LOG_LVL_INFO, "Total:%d; Free:%ld;\r\n",  OS_HeapSizeGet(), OS_GetFreeHeapSize());
        }
    }
}

void creat_usr_app_task(void)
{
    ln_pm_sleep_mode_set(ACTIVE);
    ln_pm_always_clk_disable_select(CLK_G_AES);

    if(OS_OK != OS_ThreadCreate(&g_usr_app_thread, "WifiUsrAPP", usr_app_task_entry, NULL, OS_PRIORITY_BELOW_NORMAL, USR_APP_TASK_STACK_SIZE)) {
        LN_ASSERT(1);
    }

    ble_creat_usr_app_task();

#if  WIFI_TEMP_CALIBRATE
    if(OS_OK != OS_ThreadCreate(&g_temp_cal_thread, "TempAPP", temp_cal_app_task_entry, NULL, OS_PRIORITY_BELOW_NORMAL, TEMP_APP_TASK_STACK_SIZE)) {
        LN_ASSERT(1);
    }
#endif

    /* print sdk version */
    {
        LOG(LOG_LVL_INFO, "LN882H SDK Ver: %s [build time:%s][0x%08x]\r\n", LN882H_SDK_VERSION_STRING, LN882H_SDK_BUILD_DATE_TIME, LN882H_SDK_VERSION);
    }
}
