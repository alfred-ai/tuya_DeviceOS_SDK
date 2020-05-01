#include "tuya_os_adapter.h"
#include "wifi_adapter.h"

#include "net/wlan/wlan_defs.h"
#include "net/wlan/wlan.h"

#include "common/framework/net_ctrl.h"
#include "common/framework/sysinfo.h"
#include "smartlink/sc_assistant.h"
#include "net/wlan/wlan_ext_req.h"

#include <ctype.h>

/* for fast connect*/
typedef struct bss_info {
    uint8_t  ssid[32];
    uint8_t  passwd[64];
    uint8_t  psk[32];
    uint32_t  bss_size;
    uint8_t  bss[500];
    uint8_t  wep_security;
} bss_info_t;


#define WIFI_DEBUG(...) do { \
                            printf("[wifi_adapter]: "); \
                            printf(__VA_ARGS__); \
                        } while (0)

static bss_info_t pbss_info = {0};
static char fast_flag = 0;

/*geting wifi  scan and connect event msg from net_ctrl_msg_process function in net_ctrl.c */
extern int scan_status;
extern int connect_status;

int wifi_scan_networks(SACN_AP_RESULT_S* scan_res)
{
    int ret = -1;
    int size;
    uint32_t scan_timeout_ms = 3000;
    wlan_sta_scan_results_t results;
    size = MAX_SCAN_RESULTS;
    ret = wlan_sta_scan_once();
    if (ret != 0) {
        WIFI_DEBUG("wlan sta scan cmd failed\n");
        return -1;
    }

    uint32_t end_time = OS_JiffiesToMSecs(OS_GetJiffies()) + scan_timeout_ms;
	scan_status = NET_CTRL_MSG_WLAN_SCAN_FAILED;
	while (!(scan_status == NET_CTRL_MSG_WLAN_SCAN_SUCCESS) &&
        OS_TimeBefore(OS_JiffiesToMSecs(OS_GetJiffies()), end_time)) {
        OS_MSleep(100);
    }

    if(!OS_TimeBefore(OS_JiffiesToMSecs(OS_GetJiffies()), end_time)) {
        WIFI_DEBUG("wlan sta scan timeout %d\n", scan_timeout_ms);
        return -1;
    }

    results.ap = tuya_hal_system_malloc(size * sizeof(wlan_sta_ap_t));
    if (results.ap == NULL) {
        WIFI_DEBUG("do not have the mem\n");
        return -1;
    }
    results.size = size;

    ret = wlan_sta_scan_result(&results);
    if (ret == 0) {
        int i;
        for (i = 0; i < results.num; i++) {
        scan_res->ap_if[scan_res->ap_if_count].rssi = (char)results.ap[i].level;
        scan_res->ap_if[scan_res->ap_if_count].channel = results.ap[i].channel;
        memcpy(scan_res->ap_if[scan_res->ap_if_count].bssid,\
               results.ap[i].bssid,\
               sizeof(scan_res->ap_if[scan_res->ap_if_count].bssid));
        memcpy(scan_res->ap_if[scan_res->ap_if_count].ssid,\
               results.ap[i].ssid.ssid,\
               results.ap[i].ssid.ssid_len);
        scan_res->ap_if[scan_res->ap_if_count].s_len = results.ap[i].ssid.ssid_len;
        scan_res->ap_if_count++;
        }

        tuya_hal_system_free(results.ap);
        return 0;
    }

    tuya_hal_system_free(results.ap);
    return -1;
}

#define SCAN_ASSIGN_INTERVAL 10000
uint32_t scan_assign_tick = 0;
int wifi_scan_assign_networks(SACN_AP_RESULT_S* scan_res)
{
    int ret = -1;
    int size;
    char ssid[WLAN_SSID_MAX_LEN+1];
    wlan_sta_scan_results_t results;
    wlan_sta_config_t config;
    uint32_t scan_timeout_ms = 3000;
    uint32_t tick_now;
    size = MAX_SCAN_RESULTS;
    uint8_t ssid_len = scan_res->ap_if->s_len;

    tick_now = OS_JiffiesToMSecs(OS_GetJiffies());
    if (scan_assign_tick && (scan_assign_tick + SCAN_ASSIGN_INTERVAL > tick_now))//防止多次连续调用扫描，直接获取上次的扫描结果
        goto direct_get_scan_results;

    if ((ssid_len >= 1) && (ssid_len <= WLAN_SSID_MAX_LEN)) {
        config.field = WLAN_STA_FIELD_SSID;
        memcpy(config.u.ssid.ssid, scan_res->ap_if->ssid, ssid_len);
        config.u.ssid.ssid_len = ssid_len;
        ret = wlan_sta_set_config(&config);
        if (ret != 0) {
            WIFI_DEBUG("wlan sta set ssid failed\n");
            return ret;
        }

        config.field = WLAN_STA_FIELD_SCAN_SSID;
        config.u.scan_ssid = 1;
        ret = wlan_sta_set_config(&config);
        if (ret != 0) {
            WIFI_DEBUG("wlan sta set scan assign ssid failed\n");
            return ret;
        }
    }

    wlan_sta_scan_once();

    uint32_t end_time = OS_JiffiesToMSecs(OS_GetJiffies()) + scan_timeout_ms;
	scan_status = NET_CTRL_MSG_WLAN_SCAN_FAILED;
	while (!(scan_status == NET_CTRL_MSG_WLAN_SCAN_SUCCESS) &&
        OS_TimeBefore(OS_JiffiesToMSecs(OS_GetJiffies()), end_time)) {
        OS_MSleep(20);
    }

    if(!OS_TimeBefore(OS_JiffiesToMSecs(OS_GetJiffies()), end_time)) {
        WIFI_DEBUG("wlan sta scan timeout %d\n", scan_timeout_ms);
        return -1;
    }

    scan_assign_tick = OS_JiffiesToMSecs(OS_GetJiffies());

direct_get_scan_results:
    results.ap = tuya_hal_system_malloc(size * sizeof(wlan_sta_ap_t));
    if (results.ap == NULL) {
        WIFI_DEBUG("do not have the mem\n");
        return -1;
    }
    results.size = size;
    ret = wlan_sta_scan_result(&results);
    if (ret == 0) {
    int i;
    for (i = 0; i < results.num; i++) {
        if((results.ap[i].ssid.ssid_len == scan_res->ap_if->s_len) && \
           (0 == memcmp(scan_res->ap_if->ssid, \
                     results.ap[i].ssid.ssid,\
                     results.ap[i].ssid.ssid_len))) {
        if(scan_res->ap_if->rssi == UNVALID_SIGNAL) {
             scan_res->ap_if->rssi = (char)results.ap[i].level;
        }else {
            if((char)results.ap[i].level > scan_res->ap_if->rssi) {
                scan_res->ap_if->rssi = (char)results.ap[i].level;
            }
        }

        scan_res->ap_if->channel = results.ap[i].channel;
        memcpy(scan_res->ap_if->bssid,\
               results.ap[i].bssid,\
               sizeof(scan_res->ap_if->bssid));

        scan_res->ap_if->s_len = results.ap[i].ssid.ssid_len;
        scan_res->ap_if_count++;
        }
    }
    tuya_hal_system_free(results.ap);
    return 0;
    }

    tuya_hal_system_free(results.ap);
    return -1;
}

uint8_t monitor_chan;
int wifi_set_channel(uint8_t chan)
{
	enum wlan_mode mode = wlan_if_get_mode(g_wlan_netif);
    int ret;

	if (mode == WLAN_MODE_MONITOR) {
		ret = wlan_monitor_set_channel(g_wlan_netif, (int16_t)chan);
		if (ret != 0) {
		    WIFI_DEBUG("wlan_monitor_set_channel err%d\r\n", ret);
			return -1;
		}
	} else if (mode == WLAN_MODE_HOSTAP) {
		wlan_ext_sniffer_param_t sniffer;
		if (chan == 0) {
			sniffer.dwell_time = 0;
			WIFI_DEBUG("stop sniffer\r\n");
		} else {
			sniffer.dwell_time = 10 * 1000 * 1000;
		}
		sniffer.channel = chan;
		if (wlan_ext_request(g_wlan_netif, WLAN_EXT_CMD_SET_SNIFFER, (uint32_t)&sniffer) != 0) {
			WIFI_DEBUG("set sniffer fail, chan %u, dwell time %u\r\n", sniffer.channel, sniffer.dwell_time);
			return -1;
		}
		monitor_chan = chan;
		return 0;
    }

    return 0;
}

int wifi_get_channel(uint8_t *chan)
{
    *chan = monitor_chan;
    return 0;
}

extern SNIFFER_CALLBACK snif_cb;
static int max_chan = 0;
static void recv_rawframe(uint8_t *data, uint32_t len, void *info)
{
    struct frame_info *p;
    if (len < sizeof(struct ieee80211_frame)) {
        WIFI_DEBUG("%s():%d, len %u\r\n", __func__, __LINE__, len);
        return;
    }

    if(NULL == snif_cb) {
        return;
    }

#if 0
    p = info;
    if((p->type == IEEE80211_FC_STYPE_BEACON) ||
       (p->type == IEEE80211_FC_STYPE_PROBE_RESP)) {
        if (p->ap_channel > max_chan || p->ap_channel < 1) {
            return;
        }
    }
#else 
	if (info) {
	    p = info;
		if((p->type == IEEE80211_FC_STYPE_BEACON) ||
			(p->type == IEEE80211_FC_STYPE_PROBE_RESP)) {
			if (p->ap_channel > max_chan || p->ap_channel < 1) {
				printf("p->ap_channel=%d\r\n", p->ap_channel);
				return;
			}
		}
 	}
#endif

    snif_cb((uint8_t *)data,(uint16_t)len);
}

int wifi_softap_set_sniffer(int enable)
{
    WIFI_DEBUG("%s enable:%d\n", __func__, enable);

	return wlan_monitor_set_rx_cb(g_wlan_netif, enable ? recv_rawframe : NULL);
}


static void wlan_sw_ch_cb(struct netif *nif, int16_t channel)
{
    monitor_chan = channel;
}

#define TIME_OUT_MS 120000
int wifi_set_promisc(xr_promisc_t enable)
{
    sc_assistant_fun_t sca_fun;
    sc_assistant_time_config_t config;
    int ret = -1;

    /*the sc assistant switch channel time param is no use for tuya*/
    config.time_total = TIME_OUT_MS;
    config.time_sw_ch_long = 0;
    config.time_sw_ch_short = 0;

    if (enable == XR_PROMISC_ENABLE) {
        sc_assistant_get_fun(&sca_fun);
        sc_assistant_init(g_wlan_netif, &sca_fun, &config);

        ret = sc_assistant_monitor_register_rx_cb(g_wlan_netif, recv_rawframe);
        if (ret != 0) {
            WIFI_DEBUG("%s monitor set rx cb fail\n", __func__);
            return ret;
        }
        ret = sc_assistant_monitor_register_sw_ch_cb(g_wlan_netif, wlan_sw_ch_cb);
        if (ret != 0) {
            WIFI_DEBUG("%s monitor sw ch cb fail\n", __func__);
            return ret;
        }
    }else {
        if (sc_assistant_monitor_unregister_rx_cb(g_wlan_netif, recv_rawframe)) {
            WIFI_DEBUG("%s,%d cancel rx cb fail\n", __func__, __LINE__);
            return -1;
        }
        
        if (sc_assistant_monitor_unregister_sw_ch_cb(g_wlan_netif, wlan_sw_ch_cb)) {
            WIFI_DEBUG("%s,%d cancel sw ch cb fail\n", __func__, __LINE__);
            return -1;
        }
        
        sc_assistant_deinit(g_wlan_netif);
    }
    return 0;
}

int wifi_is_link_up(struct netif * netif)
{
    if (netif && netif_is_up(netif) && netif_is_link_up(netif)) {
        return 1;
    }
    
    return -1;
}

int wifi_get_mac_address(uint8_t *mac, int mac_len)
{
    struct sysinfo *sysinfo = NULL;
    sysinfo = sysinfo_get();
    if(sysinfo) {
        memcpy(mac, sysinfo->mac_addr, IEEE80211_ADDR_LEN);
        return 0;
    }

    return -1;
}

int wifi_set_mac_address(uint8_t *mac, int mac_len)
{
    struct sysinfo *sysinfo = NULL;

    sysinfo = sysinfo_get();
    if(sysinfo) {
        memcpy(sysinfo->mac_addr,mac,SYSINFO_MAC_ADDR_LEN);
        if(sysinfo_save() == 0) {
            return 0;
        }
    }

    return -1;
}

int wifi_rf_on()
{
    return 0;
}

int wifi_rf_off()
{
    return net_sys_stop();
}

int wifi_get_pm_dtim(wlan_ext_pm_dtim_t *dtim)
{
    int ret = 0;
    ret = wlan_ext_request(g_wlan_netif, WLAN_EXT_CMD_GET_PM_DTIM, (uint32_t)(dtim));
    if (ret == -2) {
        WIFI_DEBUG("invalid arg\n");
    } else if (ret == -1) {
        WIFI_DEBUG("exec failed\n");
    }

    return ret;
}
#define  roundup(x, y)  ((((x)+((y)-1))/(y))*(y))  /* to any y */
int wifi_set_pm_dtim(int period)
{
    int ret = 0;
    wlan_ext_pm_dtim_t dtim;
    int dtim_tmp;

    if(period > 0) {
        memset(&dtim, 0, sizeof(wlan_ext_pm_dtim_t));
        ret = wifi_get_pm_dtim(&dtim);
        if(!ret && dtim.pm_join_dtim_period) {
            dtim_tmp = roundup(period, dtim.pm_join_dtim_period);
            ret = wlan_ext_request(g_wlan_netif, WLAN_EXT_CMD_SET_PM_DTIM, dtim_tmp);
            if (ret == -2) {
                WIFI_DEBUG("invalid arg\n");
            } else if (ret == -1) {
                WIFI_DEBUG("exec failed\n");
            }
        }
    } else {
        ret = -1;
    }
    return ret;
}

int wifi_set_eur_enable(int enable)
{
    int ret = 0;
    int eur_enable;
    eur_enable = enable;

    ret = wlan_ext_request(g_wlan_netif, WLAN_EXT_CMD_SET_EUR_CE, eur_enable);
    if (ret == -2) {
        WIFI_DEBUG("invalid arg\n");
    } else if (ret == -1) {
        WIFI_DEBUG("exec failed\n");
    }
    return ret;
}


int us_scan_freq_list[] = {2412, 2417, 2422, 2427, 2432, 2437, 2442, 2447, 2452, 2457, 2462};//US  1-11
int jp_scan_freq_list[] = {2412, 2417, 2422, 2427, 2432, 2437, 2442, 2447, 2452,2457, 2462, 2467, 2472, 2484};//JP  1-14
int other_scan_freq_list[] = {2412, 2417, 2422, 2427, 2432, 2437, 2442, 2447, 2452,2457, 2462, 2467, 2472};//CN, DE...  1-13

int wifi_set_scan_freq(wlan_ext_scan_freq_t *scan_freq)
{
    int ret = 0;

    ret = wlan_ext_request(g_wlan_netif, WLAN_EXT_CMD_SET_SCAN_FREQ, (uint32_t)scan_freq);
    if (ret == -2) {
        WIFI_DEBUG("invalid arg\n");
    } else if (ret == -1) {
        WIFI_DEBUG("exec failed\n");
    }

    return ret;
}

int wifi_set_countrycode(char *countrycode)
{
    int ret = 0;
    wlan_ext_scan_freq_t scan_freq;
    memset(&scan_freq,0,sizeof(wlan_ext_scan_freq_t));

    if(countrycode == NULL)
        return ret;

    if(strcmp(countrycode, "US") == 0) {
        scan_freq.freq_num = 11;
        scan_freq.freq_list = &us_scan_freq_list[0];
        max_chan = sizeof(us_scan_freq_list)/sizeof(us_scan_freq_list[0]);
    } else if(strcmp(countrycode, "JP") == 0) {
        scan_freq.freq_num = 14;
        scan_freq.freq_list = &jp_scan_freq_list[0];
        max_chan = sizeof(jp_scan_freq_list)/sizeof(jp_scan_freq_list[0]);
    } else {
        scan_freq.freq_num = 13;
        scan_freq.freq_list = &other_scan_freq_list[0];
        max_chan = sizeof(other_scan_freq_list)/sizeof(other_scan_freq_list[0]);
        if(strcmp(countrycode, "EU") == 0) {
            wifi_set_eur_enable(1);
        }
    }

    ret = wifi_set_scan_freq(&scan_freq);

    return ret;
}

int wifi_on(enum wlan_mode mode)
{
    enum wlan_mode current_mode = wlan_if_get_mode(g_wlan_netif);
    WIFI_DEBUG("wifi_on current_mode %d\r\n", current_mode);
    switch(mode) {
        case WLAN_MODE_STA :
            if (current_mode == WLAN_MODE_MONITOR) {
                wifi_set_promisc(XR_PROMISC_DISABLE);
            }
            net_switch_mode(WLAN_MODE_STA);
            break;
        case WLAN_MODE_HOSTAP :
            if (current_mode == WLAN_MODE_MONITOR) {
                wifi_set_promisc(XR_PROMISC_DISABLE);
            }
            net_switch_mode(WLAN_MODE_HOSTAP);
            break;
        case WLAN_MODE_MONITOR :
            net_switch_mode(WLAN_MODE_MONITOR);
            if(wifi_set_promisc(XR_PROMISC_ENABLE))
                WIFI_DEBUG("set promisc sc_assisant failed\n");
            break;
        default:
            WIFI_DEBUG("the wlan mode is not support\n");
    }

     WIFI_DEBUG("wifi on exit\r\n");
    return 0;
}

int wifi_off()
{
    return 0;
}

int wifi_connect(const char *ssid,const char *passwd)
{
    uint8_t *_psk;
    uint8_t ssid_len;
    char ptemp[65] = {0};
    char *p = ptemp;
    wlan_gen_psk_param_t param= {0};

    if(passwd) {
        WIFI_DEBUG("%s,ssid %s,passwd, %s\r\n", __func__, ssid, passwd);
    }else {
        WIFI_DEBUG("%s,ssid %s,passwd null\r\n", __func__, ssid);
    }
    if (ssid)
        ssid_len = strlen(ssid);
    else
        goto err;

    if (ssid_len > WLAN_SSID_MAX_LEN)
        ssid_len = WLAN_SSID_MAX_LEN;
        
    if(!fast_flag) { 
        struct sysinfo *sysinfo = NULL;
        sysinfo = sysinfo_get();
        if(sysinfo == NULL) {
            return -2;
        }
        sysinfo->sta_use_dhcp = 1;
    }

    net_switch_mode(WLAN_MODE_STA);
    wlan_sta_disable();

    if (passwd) {
        if (strlen(passwd) == 0) {// passwd is '\0'
            _psk = NULL;
        } else {
            if(!fast_flag) {
                memset(&param, 0, sizeof(wlan_gen_psk_param_t));
                param.ssid_len = strlen(ssid);
                memcpy(param.ssid, (uint8_t *)ssid, param.ssid_len);
                memcpy(param.passphrase, (uint8_t *)passwd, strlen(passwd));
                wlan_sta_gen_psk(&param);
                for(int i = 1; i < 33; i++) {
                    sprintf(p, "%02x", param.psk[i - 1]);
                    p += 2;
                }
                _psk = ptemp;
            }else {
                _psk = (uint8_t *)passwd;
            }
        }
    } else {
        _psk = NULL;
    }

    if (wlan_sta_set((uint8_t *)ssid, ssid_len, _psk)) {
        goto err;
    }

    wlan_sta_enable();

    if(!fast_flag) {
        memset(pbss_info.ssid, 0, sizeof(pbss_info.ssid));
        memset(pbss_info.passwd, 0, sizeof(pbss_info.passwd));
        memset(pbss_info.psk, 0, sizeof(pbss_info.psk));
        
        memcpy(pbss_info.ssid, ssid, strlen(ssid));
        memcpy(pbss_info.passwd, passwd, strlen(passwd));
        memcpy(pbss_info.psk, param.psk, 32);
        pbss_info.wep_security = 0;
    }

    return 0;

err:
    WIFI_DEBUG("connect ap failed\n");

    //TODO: wait dhcp ready here
    return -1;
}

int wifi_disconnect()
{
    return wlan_sta_disable();
}

int wifi_is_connected_to_ap()
{
    wlan_sta_states_t state;
    wlan_sta_state(&state);
    if (state == WLAN_STA_STATE_CONNECTED)
        return 0;
    else
        return -1;
}

uint8_t ap_ip[4] = {192,168,175,1};
uint8_t ap_gw[4] = {192,168,175,1};
uint8_t ap_mask[4] = {255,255,255,0};
int wifi_ap_start(const WF_AP_CFG_IF_S *cfg)
{
    uint8_t *_psk;
    uint8_t ssid_len = strlen((char *)cfg->ssid);
    uint8_t psk_len = strlen((char *)cfg->passwd);
    wlan_ap_config_t config;
    struct sysinfo *sysinfo = sysinfo_get();

    if (psk_len) {
        _psk = (uint8_t *)cfg->passwd;
    } else {
        _psk = NULL;
    }
    if (ssid_len > WLAN_SSID_MAX_LEN)
        ssid_len = WLAN_SSID_MAX_LEN;

#if defined(ENABLE_LAN_ENCRYPTION) && (ENABLE_LAN_ENCRYPTION==1)
    memcpy(&sysinfo->netif_ap_param.ip_addr, ap_ip, sizeof(ap_ip)/sizeof(uint8_t));
    memcpy(&sysinfo->netif_ap_param.net_mask, ap_mask, sizeof(ap_mask)/sizeof(uint8_t));
    memcpy(&sysinfo->netif_ap_param.gateway, ap_gw, sizeof(ap_gw)/sizeof(uint8_t));
#endif

    WIFI_DEBUG("ap start : ip  0x%x\n",sysinfo->netif_ap_param.ip_addr.addr);
    WIFI_DEBUG("ap start : mask  0x%x\n",sysinfo->netif_ap_param.net_mask.addr);
    WIFI_DEBUG("ap start : gateway  0x%x\n",sysinfo->netif_ap_param.gateway.addr);

    net_switch_mode(WLAN_MODE_HOSTAP);
    wlan_ap_disable();
    if (wlan_ap_set((uint8_t *)cfg->ssid, ssid_len, _psk)) {
        goto err;
    }

    config.field = WLAN_AP_FIELD_MAX_NUM_STA;
    config.u.max_num_sta = 1;
    wlan_ap_set_config(&config);

    if (wlan_ap_enable()) {
        goto err;
    };

    return 0;

err:
    WIFI_DEBUG("ap start failed\n");

    return -1;
}

int wifi_ap_stop()
{
    uint32_t link_dowm_timeout = 1000;
    uint32_t timeout = OS_GetTicks() + OS_TicksToMSecs(link_dowm_timeout);

    wlan_ap_disable();
    while ((netif_is_link_up(g_wlan_netif)) &&
           OS_TimeBeforeEqual(OS_GetTicks(), timeout)) {
        OS_MSleep(20);
    }

    return 0;
}

int wifi_get_rssi(int* rssi)
{
    int ret;
    wlan_ext_signal_t signal;
    ret = wlan_ext_request(g_wlan_netif, WLAN_EXT_CMD_GET_SIGNAL, (int)(&signal));
    if (ret == -2) {
        WIFI_DEBUG("invalid arg\n");
    } else if (ret == -1) {
        WIFI_DEBUG("exec failed\n");
    }

    *rssi = signal.rssi/2 + signal.noise;
    return 0;
}

#define TRY_FIND_SSID_TIME 3
int get_wep_security(int *is_wep_security, char *ssid, int ssid_len)
{
    int ret = -1;
    int j;
    int size;
    int find_ssid = 0;
    wlan_sta_scan_results_t results;
    uint32_t scan_timeout_ms = 3000;

    size = MAX_SCAN_RESULTS;
    WIFI_DEBUG("%s,ssid %s len %d\n", __func__, ssid, ssid_len);
    results.ap = tuya_hal_system_malloc(size * sizeof(wlan_sta_ap_t));
    if (results.ap == NULL) {
        WIFI_DEBUG("do not have the mem\n");
        return -1;
    }
    results.size = size;

    for (j = 0;j < TRY_FIND_SSID_TIME; j++) {
        ret = wlan_sta_scan_once();
        if (ret != 0) {
            Free(results.ap);
            WIFI_DEBUG("wlan sta scan cmd failed\n");
            return -1;
        }

        uint32_t end_time = OS_JiffiesToMSecs(OS_GetJiffies()) + scan_timeout_ms;
		scan_status = NET_CTRL_MSG_WLAN_SCAN_FAILED;
		while (!(scan_status == NET_CTRL_MSG_WLAN_SCAN_SUCCESS) &&
            OS_TimeBefore(OS_JiffiesToMSecs(OS_GetJiffies()), end_time)) {
            OS_MSleep(100);
        }

        if(!OS_TimeBefore(OS_JiffiesToMSecs(OS_GetJiffies()), end_time)){
            WIFI_DEBUG("wlan sta scan timeout %d\n", scan_timeout_ms);
            tuya_hal_system_free(results.ap);
            return -1;
        }

        //OS_MSleep(1500);
        ret = wlan_sta_scan_result(&results);
        if (ret == 0) {
            int i;
            for (i = 0; i < results.num; i++) {
                if((results.ap[i].ssid.ssid_len == ssid_len) && \
                    (0 == memcmp(ssid, \
                                results.ap[i].ssid.ssid,\
                                results.ap[i].ssid.ssid_len))) {
                     //WIFI_DEBUG("%s, find ssid, i %d\n", __func__, i);
                    find_ssid = 1;
                    if(results.ap[i].wpa_flags & WPA_FLAGS_WEP) {
                        *is_wep_security = 1;
                    } else {
                        *is_wep_security = 0;
                    }

                    break;
                }
            }

            if (find_ssid == 1) {
                WIFI_DEBUG("%s, find ssid, j %d\n", __func__, j);
                break;
            }
        } else {
            tuya_hal_system_free(results.ap);
            ret = -1;
            return ret;
        }
    }

    tuya_hal_system_free(results.ap);
    if(j == TRY_FIND_SSID_TIME) {
        WIFI_DEBUG("3 times scan, can not find the ssid\n");
        return -1;
    } else {
        return 0;
    }
}

int wifi_wep_connect(const char *ssid, const char *passwd)
{
    uint8_t ssid_len;
    wlan_sta_config_t config;
    uint32_t wep_open_connect_timeout_ms = 5000;
    WIFI_DEBUG("%s,ssid %s,passwd, %s\n", __func__, ssid, passwd);
    uint32_t timeout = OS_GetTicks() + OS_TicksToMSecs(wep_open_connect_timeout_ms);

    if (ssid)
        ssid_len = strlen(ssid);
    else
        goto err;


    if (ssid_len > WLAN_SSID_MAX_LEN)
        ssid_len = WLAN_SSID_MAX_LEN;

    if(!fast_flag) { 
        struct sysinfo *sysinfo = NULL;
        sysinfo = sysinfo_get();
        if(sysinfo == NULL) {
            return -2;
        }
        sysinfo->sta_use_dhcp = 1;
    }

    net_switch_mode(WLAN_MODE_STA);
    wlan_sta_disable();

    memset(&config, 0, sizeof(config));
    connect_status = NET_CTRL_MSG_WLAN_DISCONNECTED;

    /* ssid */
    config.field = WLAN_STA_FIELD_SSID;
    memcpy(config.u.ssid.ssid, ssid, ssid_len);
    config.u.ssid.ssid_len = ssid_len;
    if (wlan_sta_set_config(&config) != 0)
        goto err;

    /* WEP key0 */
    config.field = WLAN_STA_FIELD_WEP_KEY0;
    strlcpy((char *)config.u.wep_key, passwd, sizeof(config.u.wep_key));
    if (wlan_sta_set_config(&config) != 0)
        return -1;

    /* WEP key index */
    config.field = WLAN_STA_FIELD_WEP_KEY_INDEX;
    config.u.wep_tx_keyidx = 0;
    if (wlan_sta_set_config(&config) != 0)
        goto err;

    /* auth_alg: OPEN */
    config.field = WLAN_STA_FIELD_AUTH_ALG;
    config.u.auth_alg = WPA_AUTH_ALG_OPEN | WPA_AUTH_ALG_SHARED;
    if (wlan_sta_set_config(&config) != 0)
        goto err;

    /* key_mgmt: NONE */
    config.field = WLAN_STA_FIELD_KEY_MGMT;
    config.u.key_mgmt = WPA_KEY_MGMT_NONE;
    if (wlan_sta_set_config(&config) != 0)
        goto err;

    if (wlan_sta_enable()!= 0)
        goto err;

    while ((connect_status == NET_CTRL_MSG_WLAN_DISCONNECTED) &&
           OS_TimeBeforeEqual(OS_GetTicks(), timeout)) {
        OS_MSleep(20);
    }

	if (connect_status == NET_CTRL_MSG_WLAN_CONNECTED) {
        return 0;
    } else {//WLAN_EVENT_CONNECT_FAILED or timeout
        WIFI_DEBUG("%s, WPA_AUTH_ALG_SHARED\n", __func__);
        config.field = WLAN_STA_FIELD_AUTH_ALG;
        config.u.auth_alg = WPA_AUTH_ALG_SHARED;
        if (wlan_sta_set_config(&config) != 0)
            goto err;
    }

    if(!fast_flag) {
        memset(pbss_info.ssid, 0, sizeof(pbss_info.ssid));
        memset(pbss_info.passwd, 0, sizeof(pbss_info.passwd));
        memset(pbss_info.psk, 0, sizeof(pbss_info.psk));
        
        memcpy(pbss_info.ssid, ssid, strlen(ssid));
        memcpy(pbss_info.passwd, passwd, strlen(passwd));
        pbss_info.wep_security = 1;
    }
    
    return 0;
    
err:
    WIFI_DEBUG("connect ap failed\n");
    return -1;
}

void wifi_ps_enable()
{
    WIFI_DEBUG(" wifi_ps_enable\n");
    wlan_set_ps_mode(g_wlan_netif, 1);
}
int wps_pbc_start = 0;
int wifi_wps_pbc_start()
{
    int ret = 0;
    struct sysinfo *sysinfo;
    sysinfo = sysinfo_get();
    sysinfo->sta_use_dhcp = 1;

    ret = wlan_sta_wps_pbc();
    if (ret) {
        WIFI_DEBUG("sta wps start failed\n");
        return -1;
    }
    wps_pbc_start = 1;
    return ret;
}

int wifi_wps_pbc_stop()
{
    int ret = 0;
    struct netif * nif = g_wlan_netif;
    if(nif && netif_is_up(nif) && netif_is_link_up(nif) &&
        NET_IS_IP4_VALID(nif)) {
        WIFI_DEBUG("sta wps already connected\n");
        wps_pbc_start = 0;
        return 0;
    }

    if (nif) {
        if (NET_IS_IP4_VALID(nif)) {
            net_config(nif, 0);
        }

        if (netif_is_link_up(nif)) {
            wlan_sta_disable();
        }

        net_sys_stop();
    }
    ret = net_sys_start(WLAN_MODE_STA);
    if(ret) {
        printf("wlan sta wps stop err!");
        return -1;
    }
    wps_pbc_start = 0;
    return ret;
}

int wifi_wps_ap_info_get(char* ssid, char* pwd)
{
    int ret = 0;
    wlan_sta_wps_psk_t wps_psk;
    wlan_sta_ap_t ap;

    ret = wlan_sta_ap_info(&ap);
    if (ret != 0) {
        WIFI_DEBUG("wlan sta ap info err!");
        return -1;
    }

    ret = wlan_sta_wps_psk_get(&wps_psk);
    if (ret != 0) {
        WIFI_DEBUG("wlan sta wps psk err!");
        return -1;
    }

    memcpy(ssid, ap.ssid.ssid, ap.ssid.ssid_len);
    memcpy(pwd, wps_psk.pwd, strlen(wps_psk.pwd));

    return ret;
}

int wifi_fast_connect(char *ap_info)
{
    int i;
    char psk_temp[65] = {0};
    uint8_t *_psk = NULL;
    char * p = psk_temp;
    wlan_sta_bss_info_t bss_set;
    int ret = 0;
    
    if(ap_info == NULL) {
        return -1;
    }

    memset(&pbss_info, 0, sizeof(bss_info_t));
    memcpy(&pbss_info, ap_info, sizeof(bss_info_t));

    //scan_status = NET_CTRL_MSG_WLAN_SCAN_FAILED;//ap change channel case

    //printf("pbss_info ssid %s, passwd %s, fast_connected_prev %d, passwd %s\n", pbss_info.ssid,
    //	pbss_info.passwd, pbss_info.fast_connected_pre, passwd);

    #ifdef FAST_CON_DBUG
    for (i = 1; i <= 32; i++) {
        printf("0x%02x",pbss_info.psk[i-1]);
        if (i % 8== 0) {
            printf("\n");
        }
    }
    printf("\n");
    printf("next connect===========\n");
    #endif
    
    bss_set.size = pbss_info.bss_size;
    bss_set.bss = malloc(bss_set.size);
    if(bss_set.bss == NULL) {
        return -2;
    }
    memset(bss_set.bss, 0, bss_set.size);
    memcpy(bss_set.bss, pbss_info.bss, bss_set.size);
    
    #ifdef FAST_CON_DBUG
    for (i = 1; i < bss_set.size + 1; ++i) {
        printf("0x%02x, ", bss_set.bss[i-1]);
        if (i % 16 == 0) {
            printf("\n");
        }
    }
    printf("\nBSS size: %d\n", bss_set.size);
    printf("ssid %s, bss_size %d\n", (char *)pbss_info.ssid, bss_set.size);
    #endif
    
    wlan_sta_set_bss(&bss_set);
    free(bss_set.bss);

    fast_flag = 1;
    if(pbss_info.wep_security == 1) {
        ret = wifi_wep_connect(pbss_info.ssid, pbss_info.passwd);
    } else {
        if(strlen(pbss_info.passwd) != 0) {
            for(i = 1; i < 33; i++) {
                sprintf(p, "%02x", pbss_info.psk[i - 1]);
                p += 2;
            }
            *p = '\0';
            _psk = (uint8_t *)psk_temp;
        }else {//open ap
            _psk = NULL;
        }

        ret = wifi_connect(pbss_info.ssid, _psk);
    }
    fast_flag = 0;

    #ifdef FAST_CON_DBUG
    if(_psk)
        printf("psk:%s ssid: %s\n", _psk, ssid);
    printf("connect==========over=\n");
    #endif

    return ret;
}

int wifi_first_connect_save(char **apinfo,uint *len)
{
    if(apinfo == NULL) {
        return -1;
    }
    struct sysinfo *sysinfo = NULL;
    wlan_sta_bss_info_t bss_get;
    int size, i;

    sysinfo = sysinfo_get();
    if(sysinfo == NULL) {
        printf("sysinfo_get NULL!!");
        return -2;
    }

    sysinfo->sta_use_dhcp = 0;

    memset(&(sysinfo->netif_sta_param.ip_addr), 0, sizeof(sysinfo->netif_sta_param.ip_addr));
    memset(&(sysinfo->netif_sta_param.gateway), 0, sizeof(sysinfo->netif_sta_param.gateway));
    memset(&(sysinfo->netif_sta_param.net_mask), 0, sizeof(sysinfo->netif_sta_param.net_mask));
    memcpy(&(sysinfo->netif_sta_param.ip_addr), &(g_wlan_netif->ip_addr), sizeof(ip_addr_t));
    memcpy(&(sysinfo->netif_sta_param.gateway), &(g_wlan_netif->gw), sizeof(ip_addr_t));
    memcpy(&(sysinfo->netif_sta_param.net_mask), &(g_wlan_netif->netmask), sizeof(ip_addr_t));
    sysinfo_save();

    wlan_sta_get_bss_size(&size);
    if((size <= 0) || (size > 500)) {
        printf("bss size is out of range %d",size);
        return -3;
    }
    
    bss_get.size = size;
    bss_get.bss = malloc(size);
    if(bss_get.bss == NULL) {
        return -4;
    }
    
    memset(bss_get.bss, 0, size);
    wlan_sta_get_bss(&bss_get);

    pbss_info.bss_size = size;
    memset(pbss_info.bss, 0, sizeof(pbss_info.bss));
    memcpy(pbss_info.bss, bss_get.bss, size);
    free(bss_get.bss);

    *apinfo = &pbss_info;
    *len = sizeof(bss_info_t);
    
    return 0;
}

enum wlan_mode wifi_get_mode(void)
{
    return 
wlan_if_get_mode(g_wlan_netif);
}


int wifi_set_sniffer(int enable)
{
    int ret = 0;
    enum wlan_mode mode;
    static int sniffer_state = 0xFFFFFFFF;

    if(sniffer_state == enable) {
        WIFI_DEBUG("sniffer is already config:%d", enable);
        return 0;
    }

    mode = wifi_get_mode();
    if(mode != WLAN_MODE_HOSTAP) {
        return 0;
    }

    WIFI_DEBUG("softap need set sniffer :%d", enable);

    if(enable) {
       wifi_softap_set_sniffer(1);
    }else {
         ret = wifi_set_channel(0);
        if(ret != 0) {
            WIFI_DEBUG("stop sniffer failed ret:%d", ret);
            return ret;
        }

        ret = wifi_softap_set_sniffer(0);
        if(ret != 0) {
            WIFI_DEBUG("stop wifi_softap_set_sniffer failed ret:%d", ret);
            return ret;
        }
    }

    sniffer_state = enable;

    return 0;
}


