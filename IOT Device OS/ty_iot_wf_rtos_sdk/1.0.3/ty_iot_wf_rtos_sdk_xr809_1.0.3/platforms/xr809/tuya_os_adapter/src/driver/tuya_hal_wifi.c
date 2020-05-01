/***********************************************************
*  File: tuya_hal_wifi.c
*  Author:
*  Date:
***********************************************************/
#include "tuya_os_adapter.h"
#include "../errors_compat.h"

#include "lwip/inet.h"

#include "../system/tuya_hal_system_internal.h"

#include "kernel/os/FreeRTOS/os_time.h"
#include "net/wlan/wlan.h"
#include "net/wlan/wlan_defs.h"
#include "net/wlan/wlan_ext_req.h"
#include "tuya_hal_wifi.h"
#include "wifi_adapter.h"

/***********************************************************
*************************micro define***********************
***********************************************************/
#define NETIF_STA_IDX                       0       // lwip station/lwip ap interface  station/soft ap mode
#define NETIF_AP_IDX                        1       // lwip ap interface

/***********************************************************
*************************variable define********************
***********************************************************/
static uint8_t connect_flag = 0;
static char s_country_num[8] = "CN";

static WF_WK_MD_E wf_mode = WWM_STATION;

static uint32_t lp_rcnt = 0;

SNIFFER_CALLBACK snif_cb = NULL;

/***********************************************************
*************************extern define********************
***********************************************************/
extern struct netif *g_wlan_netif;

/***********************************************************
*************************function define********************
***********************************************************/
/***********************************************************
*  Function: tuya_hal_wifi_all_ap_scan
*  Input: none
*  Output: ap_ary num
*  Return: int
***********************************************************/
int tuya_hal_wifi_all_ap_scan(AP_IF_S **ap_ary, uint32_t *num)
{
    if(NULL == ap_ary || NULL == num) {
        return OPRT_INVALID_PARM;
    }

    int op_ret = OPRT_OK;
    SACN_AP_RESULT_S *scan_res = tuya_hal_system_malloc(sizeof(SACN_AP_RESULT_S));
    if(NULL == scan_res) {
        return OPRT_MALLOC_FAILED;
    }
    memset(scan_res,0,sizeof(SACN_AP_RESULT_S));

    scan_res->ap_if = tuya_hal_system_malloc(sizeof(AP_IF_S) * SCAN_MAX_AP);
    if(NULL == scan_res->ap_if) {
        op_ret = OPRT_MALLOC_FAILED;
        goto ERR_RET;
    }
    memset(scan_res->ap_if,0,sizeof(AP_IF_S) * SCAN_MAX_AP);
    scan_res->ap_if_nums = SCAN_MAX_AP;

    int ret  = 0;
	ret = wifi_scan_networks(scan_res);
	if(ret != 0) {
        op_ret = OPRT_WF_AP_SACN_FAIL;
        goto ERR_RET;
    }

    *ap_ary = scan_res->ap_if;
    *num = scan_res->ap_if_count;

    tuya_hal_system_free(scan_res);

    return OPRT_OK;

ERR_RET:
    tuya_hal_system_free(scan_res->ap_if);
    tuya_hal_system_free(scan_res);

    return op_ret;
}

/***********************************************************
*  Function: tuya_hal_wifi_assign_ap_scan
*  Input: ssid
*  Output: ap
*  Return: int
***********************************************************/
int tuya_hal_wifi_assign_ap_scan(const char *ssid, AP_IF_S **ap)
{
    if(NULL == ssid || NULL == ap) {
        return OPRT_INVALID_PARM;
    }

    int op_ret = OPRT_OK;
    SACN_AP_RESULT_S *scan_res = tuya_hal_system_malloc(sizeof(SACN_AP_RESULT_S));
    if(NULL == scan_res) {
        return OPRT_MALLOC_FAILED;
    }
    memset(scan_res,0,sizeof(SACN_AP_RESULT_S));

    scan_res->ap_if = tuya_hal_system_malloc(sizeof(AP_IF_S));
    if(NULL == scan_res->ap_if) {
        op_ret = OPRT_MALLOC_FAILED;
        goto ERR_RET;
    }
    memset(scan_res->ap_if,0,sizeof(AP_IF_S));
    scan_res->ap_if->rssi = UNVALID_SIGNAL;
    scan_res->ap_if_nums = 1;
    memcpy(scan_res->ap_if->ssid, ssid,strlen(ssid)+1);
    scan_res->ap_if->s_len = strlen(ssid);
    
    int ret  = 0;
    scan_res->ap_if_count = 0;

	ret = wifi_scan_assign_networks(scan_res);
    if(ret != 0) {
        op_ret = OPRT_WF_AP_SACN_FAIL;
        goto ERR_RET;
    }

    if(0 == scan_res->ap_if_count) {
        op_ret = OPRT_WF_NOT_FIND_ASS_AP;
        goto ERR_RET;
    }

    if(0 == scan_res->ap_if_count) {
        op_ret = OPRT_WF_NOT_FIND_ASS_AP;
        goto ERR_RET;
    }

    tuya_hal_system_free(scan_res);

    return OPRT_OK;

ERR_RET:
    tuya_hal_system_free(scan_res->ap_if);
    tuya_hal_system_free(scan_res);

    return op_ret;
}

/***********************************************************
*  Function: tuya_hal_wifi_release_ap
*  Input: ap
*  Output: none
*  Return: int
***********************************************************/
int tuya_hal_wifi_release_ap(AP_IF_S *ap)
{
    if(NULL == ap) {
        return OPRT_INVALID_PARM;
    }

    tuya_hal_system_free(ap);

    return OPRT_OK;
}

/***********************************************************
*  Function: tuya_hal_wifi_close_concurrent_ap
*  Input: ap
*  Output: none
*  Return: int
***********************************************************/
int tuya_hal_wifi_close_concurrent_ap(void)
{
    return OPRT_NOT_SUPPORTED;
}

/***********************************************************
*  Function: tuya_hal_wifi_set_cur_channel
*  Input: chan
*  Output: none
*  Return: int
***********************************************************/
int tuya_hal_wifi_set_cur_channel(const uint8_t chan)
{
    int ret = 0;

    if(0 == chan) {
        return OPRT_INVALID_PARM;
    }

    ret = wifi_set_channel(chan);
    if(ret < 0) {
        return OPRT_COM_ERROR;
    }

    return OPRT_OK;
}

/***********************************************************
*  Function: tuya_hal_wifi_get_cur_channel
*  Input: none
*  Output: chan
*  Return: int
***********************************************************/
int tuya_hal_wifi_get_cur_channel(uint8_t *chan)
{
    int ret = 0;
    
    ret = wifi_get_channel(chan);
    if(ret < 0) {
        return OPRT_COM_ERROR;
    }

    return OPRT_OK;
}

/***********************************************************
*  Function: tuya_hal_wifi_sniffer_set
*  Input: en cb
*  Output: none
*  Return: int
***********************************************************/
int tuya_hal_wifi_sniffer_set(const bool en, const SNIFFER_CALLBACK cb)
{
    int ret = OPRT_OK;

    if( en != 0 && NULL == cb) {
        return OPRT_INVALID_PARM;
    }

    if(en != 0) {
        snif_cb = cb;
        wifi_set_sniffer(1);
    }else {
        snif_cb = NULL;
        wifi_set_sniffer(0);
    }

    return ret;
}

/***********************************************************
*  Function: tuya_hal_wifi_get_ip
*  Input: wf
*  Output: ip
*  Return: int
***********************************************************/
int tuya_hal_wifi_get_ip(const WF_IF_E wf, NW_IP_S *ip)
{
    WF_WK_MD_E mode = 0;

    if(NULL == ip) {
        return OPRT_INVALID_PARM;
    }

    tuya_hal_wifi_get_work_mode(&mode);
    if((WF_STATION == wf) && (mode != WWM_STATION && mode != WWM_STATIONAP)) {
        return OPRT_COM_ERROR;
    }else if((WF_AP == wf) && (mode != WWM_SOFTAP && mode != WWM_STATIONAP)) {
        return OPRT_COM_ERROR;
    }

    int ret = 0;
    ret = wifi_is_link_up(g_wlan_netif);
    if(1 != ret) {
        return OPRT_COM_ERROR;
    }

    uint32_t ip_address = 0;

    // ip
    ip_address = g_wlan_netif->ip_addr.addr;
    sprintf(ip->ip,"%d.%d.%d.%d",(uint8_t)(ip_address),(uint8_t)(ip_address >> 8),\
                                 (uint8_t)(ip_address >> 16),(uint8_t)(ip_address >> 24));

    // gw
    ip_address = g_wlan_netif->gw.addr;
    sprintf(ip->gw,"%d.%d.%d.%d",(uint8_t)(ip_address),(uint8_t)(ip_address >> 8),\
                                 (uint8_t)(ip_address >> 16),(uint8_t)(ip_address >> 24));

    // submask
    ip_address = g_wlan_netif->netmask.addr;
    sprintf(ip->mask,"%d.%d.%d.%d",(uint8_t)(ip_address),(uint8_t)(ip_address >> 8),\
                                   (uint8_t)(ip_address >> 16),(uint8_t)(ip_address >> 24));

    return OPRT_OK;
}

/***********************************************************
*  Function: tuya_hal_wifi_set_ip
*  Input: wf
*  Output: ip
*  Return: int
***********************************************************/
int tuya_hal_wifi_set_ip(const WF_IF_E wf, const NW_IP_S *ip)
{
    return OPRT_NOT_SUPPORTED;
}

/***********************************************************
*  Function: tuya_hal_wifi_get_bssid
*  Input: mac
*  Output: mac
*  Return: int
***********************************************************/
int tuya_hal_wifi_get_bssid(uint8_t mac[6])
{
    return OPRT_NOT_SUPPORTED;
}

/***********************************************************
*  Function: tuya_hal_wifi_get_mac
*  Input: wf
*  Output: mac
*  Return: int
***********************************************************/
int tuya_hal_wifi_get_mac(const WF_IF_E wf, NW_MAC_S *mac)
{
    int ret = 0;

    if(NULL == mac) {
        return OPRT_INVALID_PARM;
    }
    
    ret = wifi_get_mac_address((uint8_t *)mac->mac, sizeof(mac->mac));
    if(ret != 0) {
        return OPRT_COM_ERROR;
    }

    return OPRT_OK;
}

/***********************************************************
*  Function: tuya_hal_wifi_set_mac
*  Input: wf mac
*  Output: none
*  Return: int
***********************************************************/
int tuya_hal_wifi_set_mac(const WF_IF_E wf, const NW_MAC_S *mac)
{
    int ret = 0;

    if(NULL == mac) {
        return OPRT_INVALID_PARM;
    }

    ret = wifi_set_mac_address((uint8_t *)mac->mac, sizeof(mac->mac));
    if(ret != 0) {
        return OPRT_COM_ERROR;
    }

    return OPRT_OK;
}

/***********************************************************
*  Function: tuya_hal_wifi_set_work_mode
*  Input: mode
*  Output: none
*  Return: int
***********************************************************/
int tuya_hal_wifi_set_work_mode(const WF_WK_MD_E mode)
{
    int ret = 0;
    
    if((WWM_LOWPOWER == wf_mode) && (mode != WWM_LOWPOWER)) {
        ret = wifi_rf_on();
        if(ret != 0) {
            return OPRT_COM_ERROR;
        }
    }

    ret = wifi_off();
    if(ret != 0) {
        return OPRT_COM_ERROR;
    }

    switch(mode) {
        case WWM_LOWPOWER : {
            ret = wifi_rf_off();
        }
        break;

        case WWM_SNIFFER: {
            ret = wifi_on(WLAN_MODE_MONITOR);
        }
        break;

        case WWM_STATION: {
            ret = wifi_on(WLAN_MODE_STA);
            wifi_set_countrycode(s_country_num);
            wlan_sta_bss_max_count(32);
        }
        break;

        case WWM_SOFTAP: {
            ret = wifi_on(WLAN_MODE_HOSTAP);
        }
        break;

        case WWM_STATIONAP: {
            return OPRT_COM_ERROR;
        }
        break;
    }

    if(ret != 0) {
        ret = wifi_off();
        ret |= wifi_rf_off();
        wf_mode = WWM_LOWPOWER;
        return OPRT_COM_ERROR;
    }
    
    wf_mode = mode;

    return OPRT_OK;
}

/***********************************************************
*  Function: tuya_hal_wifi_get_work_mode
*  Input: none
*  Output: mode
*  Return: OPERATE_RET
***********************************************************/
int tuya_hal_wifi_get_work_mode(WF_WK_MD_E *mode)
{
    if(NULL == mode) {
        return OPRT_INVALID_PARM;
    }
    
    *mode = wf_mode;
    
    return OPRT_OK;
}

/***********************************************************
*  Function: tuya_hal_wifi_station_connect
*  Input: ssid passwd
*  Output: mode
*  Return: int
***********************************************************/
int tuya_hal_wifi_station_connect(const char *ssid, const char *passwd)
{
    int ret = 0;
    int passwd_len = 0;
    int ssid_len = 0;
    int is_wep_security = 0;

    if(passwd) {
        passwd_len = strlen(passwd);
    }

    if(ssid) {
        ssid_len = strlen(ssid);
    }

    if(5 == passwd_len) {
        is_wep_security = 1;
    }

    if((13 == passwd_len) | (10 == passwd_len) |
        (26 == passwd_len)) {
        ret = get_wep_security(&is_wep_security, (char *)ssid, ssid_len);
        if(ret < 0) {
            return OPRT_COM_ERROR;
        }
    }

    if(is_wep_security == 1) {
        ret = wifi_wep_connect(ssid, passwd);
    } else {
        ret = wifi_connect(ssid, passwd);
    }
    if (ret != 0)
        return OPRT_COM_ERROR;

    return OPRT_OK;

}

/***********************************************************
*  Function: tuya_hal_wifi_station_disconnect
*  Input: none
*  Output: none
*  Return: int
***********************************************************/
int tuya_hal_wifi_station_disconnect(void)
{
    int ret = 0;

    ret = wifi_disconnect();
    if(ret != 0) {
        return OPRT_COM_ERROR;
    }
	
	connect_flag = 0;
	
    return OPRT_OK;
}

/***********************************************************
*  Function: tuya_hal_wifi_station_get_conn_ap_rssi
*  Input: none
*  Output: rssi
*  Return: int
***********************************************************/
int tuya_hal_wifi_station_get_conn_ap_rssi(int8_t *rssi)
{
    int ret = 0;
    int tmp_rssi = 0;

    if(NULL == rssi) {
        return OPRT_INVALID_PARM;
    }

	if(wifi_is_connected_to_ap() != 0) {
		return OPRT_COM_ERROR;
	}
	
    ret = wifi_get_rssi(&tmp_rssi);
    if(ret < 0) {
        return OPRT_COM_ERROR;
    }

    *rssi = tmp_rssi;

    return OPRT_OK;
}

/***********************************************************
*  Function: tuya_hal_wifi_station_get_ap_mac
*  Input: none
*  Output: mac
*  Return: int
***********************************************************/
int tuya_hal_wifi_station_get_ap_mac(NW_MAC_S *mac)
{
    return OPRT_NOT_SUPPORTED;
}

/***********************************************************
*  Function: tuya_hal_wifi_station_get_status
*  Input: none
*  Output: stat
*  Return: int
***********************************************************/
int tuya_hal_wifi_station_get_status(WF_STATION_STAT_E *stat)
{
    int ret = 0;
    static WF_STATION_STAT_E last_stat = WSS_IDLE;
    ret = wifi_is_connected_to_ap();
    if(0 != ret) {
        *stat = WSS_IDLE;
        last_stat = WSS_IDLE;
        return OPRT_OK;
    }

    if(0 == (g_wlan_netif->flags & NETIF_FLAG_UP)) {
        *stat = WSS_CONN_SUCCESS;
        last_stat = WSS_CONN_SUCCESS;
        return OPRT_OK;
    }

    if(0 == (g_wlan_netif->flags & NETIF_FLAG_LINK_UP)) {
        *stat = WSS_CONN_SUCCESS;
        last_stat = WSS_CONN_SUCCESS;
        return OPRT_OK;
    }

    if (g_wlan_netif->ip_addr.addr == INADDR_ANY) {
        *stat = WSS_CONN_SUCCESS;
        last_stat = WSS_CONN_SUCCESS;
        return OPRT_OK;
    }

    *stat = WSS_GOT_IP;
    if(last_stat != WSS_GOT_IP) {
        last_stat = WSS_GOT_IP;
        wifi_ps_enable();
    }

    return OPRT_OK;

}

/***********************************************************
*  Function: hwl_wf_ap_start
*  Input: cfg
*  Output: none
*  Return: int
***********************************************************/
int tuya_hal_wifi_ap_start(const WF_AP_CFG_IF_S *cfg)
{
	int ret = -1;
    if(NULL == cfg) {
        return OPRT_INVALID_PARM;
    }

    WF_WK_MD_E mode = 0;
    tuya_hal_wifi_get_work_mode(&mode);
    if(WWM_SOFTAP != mode && WWM_STATIONAP != mode) {
        return OPRT_COM_ERROR;
    }
	
	ret = wifi_ap_start(cfg);
	if (ret != 0){
		return OPRT_COM_ERROR;
	}

    return OPRT_OK;
}

/***********************************************************
*  Function: tuya_hal_wifi_ap_stop
*  Input: none
*  Output: none
*  Return: int
***********************************************************/
int tuya_hal_wifi_ap_stop(void)
{
	int ret = -1;
	ret = wifi_ap_stop();
	if (ret != 0){
		return OPRT_COM_ERROR;
	}
    return OPRT_OK;
}

/***********************************************************
*  Function: tuya_hal_wifi_set_country_code
*  Input:  p_country_code  country code
*  Output: none
*  Return: int
***********************************************************/
int tuya_hal_wifi_set_country_code(const char *p_country_code)
{
    if(NULL == p_country_code) {
        return OPRT_INVALID_PARM;
    }

    strcpy(s_country_num, p_country_code);

    return OPRT_OK;
}

/***********************************************************
*  Function: tuya_hal_wifi_get_cur_country_code
*  Input: none
*  Output: none
*  Return: COUNTRY_CODE_E: country code
***********************************************************/
COUNTRY_CODE_E tuya_hal_wifi_get_cur_country_code(void)
{
    COUNTRY_CODE_E code = COUNTRY_CODE_CN;

    if(0 == strcmp(s_country_num, "CN")) {
        code = COUNTRY_CODE_CN;
    }else if(0 == strcmp(s_country_num, "US")) {
        code = COUNTRY_CODE_US;
    }else if(0 == strcmp(s_country_num, "JP")) {
        code = COUNTRY_CODE_JP;
    }else if(0 == strcmp(s_country_num, "EU")) {
        code = COUNTRY_CODE_EU;
    }else {
        code = COUNTRY_CODE_CN;
    }

    return code;
}

/***********************************************************
*  Function: tuya_hal_wifi_get_rf_cal_flag
*  Input: none
*  Output: none
*  Return: int
***********************************************************/
bool tuya_hal_wifi_get_rf_cal_flag(void)
{
    return 0;
}

/***********************************************************
*  Function: tuya_hal_wifi_lowpower_enable
*  Input: none
*  Output: none
*  Return: int
***********************************************************/
int tuya_hal_wifi_lowpower_enable(void)
{
    if(!tuya_hal_get_lp_mode()) {
        return OPRT_COM_ERROR;
    }

    if(lp_rcnt > 0) {
        lp_rcnt--;
    }
    
    if(!lp_rcnt) {
        //pmu_release_wakelock(PMU_DEV_USER_BASE);
    }
    
    return OPRT_OK;
}
/***********************************************************
*  Function: tuya_hal_wifi_lowpower_disable
*  Input: none
*  Output: none
*  Return: int
***********************************************************/
int tuya_hal_wifi_lowpower_disable(void)
{
    if(!tuya_hal_get_lp_mode()) {
        return OPRT_COM_ERROR;
    }
    
    if(!lp_rcnt++) {
        //pmu_acquire_wakelock(PMU_DEV_USER_BASE); //acquire wakelock
    }

    return OPRT_OK;
}

/***********************************************************
*  Function: tuya_hal_wifi_send_mgnt
*  Input:    buf         pointer to buffer
             len         length of buffer
*  Output: none
*  Return: int
***********************************************************/
int tuya_hal_wifi_send_mgnt(const uint8_t *buf, const uint32_t len)
{
    return OPRT_OK;
}

/***********************************************************
*  Function: tuya_hal_wifi_register_recv_mgnt_callback
*  Input:    enable
             recv_cb     receive callback
*  Output: none
*  Return: int
***********************************************************/
int tuya_hal_wifi_register_recv_mgnt_callback(bool enable, WIFI_REV_MGNT_CB recv_cb)
{
    return OPRT_OK;
}

/***********************************************************
*  Function: tuya_hal_wifi_set_socket_broadcast_all
*  Input:    socket_fd
             enable
*  Output: none
*  Return: int
***********************************************************/
int tuya_hal_wifi_set_socket_broadcast_all(const int socket_fd, const bool enable)
{
	return OPRT_OK;
}

/***********************************************************
*  Function: tuya_hal_wifi_wps_pbc_start
*  Input: none
*  Output: none
*  Return: int
***********************************************************/
int tuya_hal_wifi_wps_pbc_start(void) 
{
    return OPRT_NOT_SUPPORTED;
}

/***********************************************************
*  Function: tuya_hal_wifi_wps_ap_info_get
*  Input: none
*  Output:   ssid
             pwd
*  Return: int
***********************************************************/
int tuya_hal_wifi_wps_ap_info_get(uint8_t* ssid, uint8_t* pwd)
{
    return OPRT_NOT_SUPPORTED;
}

/***********************************************************
*  Function: tuya_hal_wifi_wps_pbc_stop
*  Input: none
*  Output: none
*  Return: int
***********************************************************/
int tuya_hal_wifi_wps_pbc_stop(void)
{
    return OPRT_NOT_SUPPORTED;
}

/***********************************************************
*  Function: tuya_hal_wifi_get_connected_ap_info_v2
*  Input:    none
*  Output:   fast_ap_info
*  Return: int
***********************************************************/
int tuya_hal_wifi_get_connected_ap_info_v2(void **fast_ap_info)
{
    char *apinfo = NULL;
    uint32_t len = 0;
    FAST_WF_CONNECTED_AP_INFO_V2_S *ap_infor_v2_buf = NULL;

    if(NULL == fast_ap_info) {
        return OPRT_INVALID_PARM;
    }

    if(0 != wifi_first_connect_save(&apinfo, &len)) {
        return OPRT_COM_ERROR;
    }

    ap_infor_v2_buf = (FAST_WF_CONNECTED_AP_INFO_V2_S *)tuya_hal_system_malloc(sizeof(FAST_WF_CONNECTED_AP_INFO_V2_S)+len);
    if(NULL == ap_infor_v2_buf) {
        return OPRT_MALLOC_FAILED;
    }

    ap_infor_v2_buf->len = len;
    memcpy(ap_infor_v2_buf->data, apinfo, len);

    *fast_ap_info = (void *)ap_infor_v2_buf;

    return OPRT_OK;
}

/***********************************************************
*  Function: tuya_hal_fast_station_connect_v2
*  Input:    fast_ap_info
*  Output:   none
*  Return:   int
***********************************************************/
int tuya_hal_fast_station_connect_v2( FAST_WF_CONNECTED_AP_INFO_V2_S *fast_ap_info)
{
    int op_ret = OPRT_OK;
    
    op_ret = wifi_fast_connect((char *)fast_ap_info->data);

    return OPRT_OK;
}


