#include "osal/osal.h"
#include "utils/debug/log.h"
#include "utils/debug/ln_assert.h"
#include "utils/system_parameter.h"
#include "utils/ln_psk_calc.h"
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
#include "usr_app.h"

#include "rwip_config.h"
#include "llm_int.h"
#include "ln_app_gatt.h"
#include "ln_app_gap.h"
#include "gapm_task.h"
#include "ln_app_gap.h"
#include "ln_app_gatt.h"
#include "ln_app_callback.h"
#include "ln_def.h"
#include "usr_send_data.h"

#define DEVICE_NAME                  ("LN_data_trans+-*/")
#define DEVICE_NAME_LEN              (sizeof(DEVICE_NAME))
#define ADV_DATA_MAX_LENGTH          (28)

extern uint8_t svc_uuid[16];
extern uint8_t con_num;
static OS_Thread_t ble_g_usr_app_thread;
#define BLE_USR_APP_TASK_STACK_SIZE  (1024)

uint8_t adv_actv_idx  =0;
uint8_t init_actv_idx =0;

static OS_Thread_t g_usr_app_thread;
#define USR_APP_TASK_STACK_SIZE   6*256 //Byte

#define WIFI_TEMP_CALIBRATE             1//1

#if WIFI_TEMP_CALIBRATE
static OS_Thread_t g_temp_cal_thread;
#define TEMP_APP_TASK_STACK_SIZE   4*256 //Byte
#endif

/* declaration */
static void wifi_init_ap(void);
static void wifi_init_sta(void);
static void usr_app_task_entry(void *params);
static void temp_cal_app_task_entry(void *params);

static uint8_t mac_addr[6]        = {0x00, 0x50, 0xC2, 0x5E, 0x88, 0x99};
static uint8_t psk_value[40]      = {0x0};
// static uint8_t target_ap_bssid[6] = {0xC0, 0xA5, 0xDD, 0x84, 0x6F, 0xA8};

wifi_sta_connect_t connect = {
    .ssid    = "A_Murphy",
    .pwd     = "12345678",
    .bssid   = NULL,
    .psk_value = NULL,
};

wifi_scan_cfg_t scan_cfg = {
        .channel   = 0,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time = 20,
};

wifi_softap_cfg_t ap_cfg = {
    .ssid            = "LN_AP_8899",
    .pwd             = "12345678",
    .bssid           = mac_addr,
    .ext_cfg = {
        .channel         = 6,
        .authmode        = WIFI_AUTH_WPA_WPA2_PSK,//WIFI_AUTH_OPEN,
        .ssid_hidden     = 0,
        .beacon_interval = 100,
        .psk_value = NULL,
    }
};

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
    ln_generate_random_mac(mac_addr);

    //1. net device(lwip)
    netdev_set_mac_addr(NETIF_IDX_STA, mac_addr);
    netdev_set_active(NETIF_IDX_STA);
    sysparam_sta_mac_update((const uint8_t *)mac_addr);

    //2. wifi start
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

    wifi_sta_connect(&connect, &scan_cfg);
}

static void ap_startup_cb(void * arg)
{
    netdev_set_state(NETIF_IDX_AP, NETDEV_UP);
}

static void wifi_init_ap(void)
{
    tcpip_ip_info_t  ip_info;
    server_config_t  server_config;

    ip_info.ip.addr      = ipaddr_addr((const char *)"192.168.4.1");
    ip_info.gw.addr      = ipaddr_addr((const char *)"192.168.4.1");
    ip_info.netmask.addr = ipaddr_addr((const char *)"255.255.255.0");

    server_config.server.addr   = ip_info.ip.addr;
    server_config.port          = 67;
    server_config.lease         = 2880;
    server_config.renew         = 2880;
    server_config.ip_start.addr = ipaddr_addr((const char *)"192.168.4.100");
    server_config.ip_end.addr   = ipaddr_addr((const char *)"192.168.4.150");
    server_config.client_max    = 3;
    dhcpd_curr_config_set(&server_config);

    //1. net device(lwip).
    netdev_set_mac_addr(NETIF_IDX_AP, mac_addr);
    netdev_set_ip_info(NETIF_IDX_AP, &ip_info);
    netdev_set_active(NETIF_IDX_AP);
    wifi_manager_reg_event_callback(WIFI_MGR_EVENT_SOFTAP_STARTUP, &ap_startup_cb);

    sysparam_softap_mac_update((const uint8_t *)mac_addr);

    ap_cfg.ext_cfg.psk_value = NULL;
    if ((strlen(ap_cfg.pwd) != 0) &&
        (ap_cfg.ext_cfg.authmode != WIFI_AUTH_OPEN) &&
        (ap_cfg.ext_cfg.authmode != WIFI_AUTH_WEP)) {
        memset(psk_value, 0, sizeof(psk_value));
        if (0 == ln_psk_calc(ap_cfg.ssid, ap_cfg.pwd, psk_value, sizeof (psk_value))) {
            ap_cfg.ext_cfg.psk_value = psk_value;
            hexdump(LOG_LVL_INFO, "psk value ", psk_value, sizeof(psk_value));
        }
    }

    //2. wifi
    if(WIFI_ERR_NONE !=  wifi_softap_start(&ap_cfg)){
        LOG(LOG_LVL_ERROR, "[%s, %d]wifi_start() fail.\r\n", __func__, __LINE__);
    }
}


static void usr_app_task_entry(void *params)
{
    LN_UNUSED(params);

    // hal_sleep_set_mode(ACTIVE);

    wifi_manager_init();

    wifi_init_sta();
    // wifi_init_ap();


    while(NETDEV_LINK_UP != netdev_get_link_state(netdev_get_active())){
        OS_MsDelay(1000);
    }
    while(1)
    {
        OS_MsDelay(1000);
    }
}

static void temp_cal_app_task_entry(void *params)
{
    LN_UNUSED(params);

    int8_t cap_comp = 0;
    uint16_t adc_val = 0;

    if (NVDS_ERR_OK == ln_nvds_get_tx_power_comp((uint8_t *)&cap_comp)) {
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
    }
}

static void app_create_advertising(void)
{
#define APP_ADV_CHMAP                (0x07)  // Advertising channel map - 37, 38, 39
#define APP_ADV_INT_MIN              (640)   // Advertising minimum interval - 40ms (64*0.625ms)
#define APP_ADV_INT_MAX              (640)   // Advertising maximum interval - 40ms (64*0.625ms)

	struct ln_gapm_activity_create_adv_cmd  adv_creat_param = {0};

	adv_creat_param.own_addr_type                     = GAPM_STATIC_ADDR;
	adv_creat_param.adv_param.type                    = GAPM_ADV_TYPE_LEGACY;//GAPM_ADV_TYPE_EXTENDED;//GAPM_ADV_TYPE_LEGACY;
	adv_creat_param.adv_param.filter_pol              = ADV_ALLOW_SCAN_ANY_CON_ANY;
	adv_creat_param.adv_param.prim_cfg.chnl_map       = APP_ADV_CHMAP;
	adv_creat_param.adv_param.prim_cfg.phy            = GAP_PHY_1MBPS;
	adv_creat_param.adv_param.prop                    = GAPM_ADV_PROP_UNDIR_CONN_MASK;//GAPM_ADV_PROP_NON_CONN_SCAN_MASK;//GAPM_ADV_PROP_UNDIR_CONN_MASK;//GAPM_ADV_PROP_UNDIR_CONN_MASK;//GAPM_EXT_ADV_PROP_UNDIR_CONN_MASK;//GAPM_ADV_PROP_UNDIR_CONN_MASK;
	adv_creat_param.adv_param.disc_mode               = GAPM_ADV_MODE_GEN_DISC;
	adv_creat_param.adv_param.prim_cfg.adv_intv_min   = APP_ADV_INT_MIN;
	adv_creat_param.adv_param.prim_cfg.adv_intv_max   = APP_ADV_INT_MAX;
	adv_creat_param.adv_param.max_tx_pwr              = 0;
	//adv_creat_param.adv_param.second_cfg.phy        = GAP_PHY_1MBPS;//GAP_PHY_1MBPS;//GAP_PHY_CODED;
	adv_creat_param.adv_param.second_cfg.max_skip     = 0x00;
	adv_creat_param.adv_param.second_cfg.phy          = 0x01;
	adv_creat_param.adv_param.second_cfg.adv_sid      = 0x00;
	adv_creat_param.adv_param.period_cfg.adv_intv_min = 0x0400;
	adv_creat_param.adv_param.period_cfg.adv_intv_max = 0x0400;
	ln_app_advertise_creat(&adv_creat_param);
}

static void app_set_adv_data(void)
{
	//adv data: adv length--adv type--adv string ASCII
	uint8_t adv_data[ADV_DATA_MAX_LENGTH] = {0};
    
	adv_data[0] = DEVICE_NAME_LEN + 1;
	adv_data[1] = 0x09;  //adv type :local name
	memcpy(&adv_data[2],DEVICE_NAME,DEVICE_NAME_LEN);

	struct ln_gapm_set_adv_data_cmd *adv_data_param = blib_malloc(sizeof(struct ln_gapm_set_adv_data_cmd) + sizeof(adv_data) );
    LN_MALLOC_CHECK(adv_data_param != NULL);
    if(adv_data_param != NULL)
    {
    	adv_data_param->actv_idx = adv_actv_idx;
    	adv_data_param->length = sizeof(adv_data);
    	memcpy(adv_data_param->data,adv_data,adv_data_param->length);
    	ln_app_set_adv_data(adv_data_param);
    	blib_free(adv_data_param);
    }
}

static void app_start_advertising(void)
{
	struct ln_gapm_activity_start_cmd  adv_start_param;
	adv_start_param.actv_idx = adv_actv_idx;
	adv_start_param.u_param.adv_add_param.duration = 0;
	adv_start_param.u_param.adv_add_param.max_adv_evt = 0;
	ln_app_advertise_start(&adv_start_param);
}

void app_restart_adv(void)
{
	app_start_advertising();
}

void app_create_init(void)
{
	struct ln_gapm_activity_create_adv_cmd init_creat_param;
	init_creat_param.own_addr_type = GAPM_STATIC_ADDR;
	ln_app_init_creat(&init_creat_param);
}

static void app_start_init(void)
{
	uint8_t peer_addr[6]= {0x12,0x34,0x56,0x78,0x90,0xab};
	struct ln_gapm_activity_start_cmd  init_start_param = {0};
    
	init_start_param.actv_idx                                        = init_actv_idx;
	init_start_param.u_param.init_param.type                         = GAPM_INIT_TYPE_DIRECT_CONN_EST;//GAPM_INIT_TYPE_DIRECT_CONN_EST;
	init_start_param.u_param.init_param.prop                         = GAPM_INIT_PROP_1M_BIT;//GAPM_INIT_PROP_CODED_BIT;
	init_start_param.u_param.init_param.conn_to                      = 0;
	init_start_param.u_param.init_param.scan_param_1m.scan_intv      = 16; //16*0.625 ms=10ms
	init_start_param.u_param.init_param.scan_param_1m.scan_wd        = 16;// 16*0.625ms=10ms
	init_start_param.u_param.init_param.conn_param_1m.conn_intv_min  = 80; // 10x1.25ms  (7.5ms--4s)
	init_start_param.u_param.init_param.conn_param_1m.conn_intv_max  = 80; // 10x1.25ms  (7.5ms--4s)
	init_start_param.u_param.init_param.conn_param_1m.conn_latency   = 0;
	init_start_param.u_param.init_param.conn_param_1m.supervision_to = 500; //100x10ms= 1 s
	init_start_param.u_param.init_param.conn_param_1m.ce_len_min     = 0;
	init_start_param.u_param.init_param.conn_param_1m.ce_len_max     = 0;
	init_start_param.u_param.init_param.peer_addr.addr_type          = 0;
	memcpy(init_start_param.u_param.init_param.peer_addr.addr.addr, peer_addr, GAP_BD_ADDR_LEN);

	ln_app_init_start(&init_start_param);
}

 void app_restart_init(void)
{
	app_start_init();
}

static void start_adv(void)
{
	app_create_advertising();
	app_set_adv_data();
	app_start_advertising();
}

static void start_init(void)
{
	app_create_init();
	app_start_init();
}

static void ble_app_task_entry(void *params)
{
	rw_queue_msg_t usr_msg;
#if (SLAVE)
	start_adv();
#endif
#if (MASTER)
	start_init();
#endif
#if SERVICE
	data_trans_svc_add();
#endif

	while(1)
	{
        if(OS_OK == usr_queue_msg_recv((void *)&usr_msg, OS_WAIT_FOREVER))
		{
            LOG(LOG_LVL_TRACE, "connect device number :%d \r\n",con_num);
			switch(usr_msg.id)
			{
                case BLE_MSG_WRITE_DATA:
                {
                    struct ln_attc_write_req_ind *p_param = (struct ln_attc_write_req_ind *)usr_msg.msg;
                    struct ln_gattc_send_evt_cmd *send_data = (struct ln_gattc_send_evt_cmd *)blib_malloc(sizeof(struct ln_gattc_send_evt_cmd)+p_param->length);
                    LN_MALLOC_CHECK(send_data != NULL);
                    hexdump(LOG_LVL_INFO, "[recv data]", (void *)p_param->value, p_param->length);
                    if(send_data != NULL)
                    {
                        send_data->handle = p_param->handle + 2;
                        send_data->length = p_param->length;
                        memcpy(send_data->value,p_param->value,p_param->length);
                        ln_app_gatt_send_ntf(p_param->conidx,send_data);
                        blib_free(send_data);
                    }
                }
                break;

                case BLE_MSG_CONN_IND:
                {
                    struct ln_gapc_connection_req_info *p_param=(struct ln_gapc_connection_req_info *)usr_msg.msg;
#if (CLIENT)
                    struct ln_gattc_disc_cmd *param_ds = (struct ln_gattc_disc_cmd *)blib_malloc(sizeof(struct ln_gattc_disc_cmd)  + sizeof(svc_uuid));
                    LN_MALLOC_CHECK(param_ds != NULL);
                    if(param_ds != NULL)
                    {
                        param_ds->operation = GATTC_DISC_BY_UUID_SVC;
                        param_ds->start_hdl = 1;
                        param_ds->end_hdl   = 0xFFFF;
                        param_ds->uuid_len  =sizeof(svc_uuid);
                        memcpy(param_ds->uuid,svc_uuid,sizeof(svc_uuid));
                        ln_app_gatt_discovery(p_param->conidx, param_ds);
                        blib_free(param_ds);
                    }

#endif
                    ln_app_gatt_exc_mtu(p_param->conidx);
                    struct gapc_set_le_pkt_size_cmd pkt_size;
                    pkt_size.tx_octets = 251;
                    pkt_size.tx_time   = 2120;
                    OS_MsDelay(1000);
                    ln_app_param_set_pkt_size(p_param->conidx,  &pkt_size);

                    struct ln_gapc_conn_param conn_param;
                    conn_param.intv_min = 80;  // 10x1.25ms  (7.5ms--4s)
                    conn_param.intv_max = 90;  // 10x1.25ms  (7.5ms--4s)
                    conn_param.latency  = 10;
                    conn_param.time_out = 3000;  //ms*n
                    ln_app_update_param(p_param->conidx, &conn_param);
                }
                break;

                case BLE_MSG_SVR_DIS:
                {
                    struct ln_gattc_disc_svc *p_param = (struct ln_gattc_disc_svc *)usr_msg.msg;
#if (CLIENT)
                    uint8_t data[] = {0x12,0x78,0x85};
                    struct ln_gattc_write_cmd *param_wr = (struct ln_gattc_write_cmd *)blib_malloc(sizeof(struct ln_gattc_write_cmd) + sizeof(data));
                    LN_MALLOC_CHECK(param_wr != NULL);
                    if(param_wr != NULL)
                    {
                        param_wr->operation    = GATTC_WRITE;
                        param_wr->auto_execute = true;
                        param_wr->handle       = p_param->start_hdl + 2;
                        param_wr->length       = sizeof(data);
                        memcpy(&(param_wr->value[0]),&data,param_wr->length);
                        param_wr->offset = 0;
                        ln_app_gatt_write(p_param->conidx,param_wr);
                        blib_free(param_wr);
                    }
#endif
                }
                break;

                default:
                    break;
			}
            blib_free(usr_msg.msg);
		}
	}
}

void creat_usr_app_task(void)
{
    if(OS_OK != OS_ThreadCreate(&g_usr_app_thread, "WifiUsrAPP", usr_app_task_entry, NULL, OS_PRIORITY_BELOW_NORMAL, USR_APP_TASK_STACK_SIZE)) {
        LN_ASSERT(1);
    }
    
    if(OS_OK != OS_ThreadCreate(&ble_g_usr_app_thread, "BleUsrAPP", ble_app_task_entry, NULL, OS_PRIORITY_BELOW_NORMAL, BLE_USR_APP_TASK_STACK_SIZE)) 
    {
        LN_ASSERT(1);
    }

#if  WIFI_TEMP_CALIBRATE
    if(OS_OK != OS_ThreadCreate(&g_temp_cal_thread, "TempAPP", temp_cal_app_task_entry, NULL, OS_PRIORITY_BELOW_NORMAL, TEMP_APP_TASK_STACK_SIZE)) {
        LN_ASSERT(1);
    }
#endif
}