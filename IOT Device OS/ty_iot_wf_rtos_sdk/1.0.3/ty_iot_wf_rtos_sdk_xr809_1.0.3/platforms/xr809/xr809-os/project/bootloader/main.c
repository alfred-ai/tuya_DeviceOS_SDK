/*
 * Copyright (C) 2017 XRADIO TECHNOLOGY CO., LTD. All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the
 *       distribution.
 *    3. Neither the name of XRADIO TECHNOLOGY CO., LTD. nor the names of
 *       its contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdint.h>
#if defined(__CONFIG_BIN_COMPRESS) || defined(__CONFIG_IMG_COMPRESS)
#include <stdlib.h>
#include "xz/xz.h"
#include "kernel/os/os_time.h"
#endif
#include "driver/chip/system_chip.h"
#include "driver/chip/hal_chip.h"
#include "sys/image.h"
#if defined(__CONFIG_IMG_COMPRESS)
#include "sys/ota.h"
#include "sys/ota_opt.h"
#endif

#include "common/board/board.h"
#include "bl_debug.h"

#define BL_INVALID_APP_ENTRY	0xFFFFFFFFU

static __inline void bl_upgrade(void)
{
//	HAL_PRCM_SetCPUABootFlag(PRCM_CPUA_BOOT_FROM_COLD_RESET);
	HAL_PRCM_SetCPUABootFlag(PRCM_CPUA_BOOT_FROM_SYS_UPDATE);
	HAL_WDG_Reboot();
}

static __inline void bl_hw_init(void)
{
	if (HAL_Flash_Init(PRJCONF_IMG_FLASH) != HAL_OK) {
		BL_ERR("flash init fail\n");
	}
}

static __inline void bl_hw_deinit(void)
{
	HAL_Flash_Deinit(PRJCONF_IMG_FLASH);
#if PRJCONF_UART_EN
#if BL_DBG_ON
	while (!HAL_UART_IsTxEmpty(HAL_UART_GetInstance(BOARD_MAIN_UART_ID))) { }
#endif
	board_uart_deinit(BOARD_MAIN_UART_ID);
#endif
	SystemDeInit(0);
}

static uint32_t bl_load_app_bin(void)
{
	extern const unsigned char __RAM_BASE[]; /* SRAM start address */
	uint32_t len;
	section_header_t sh;

	len = image_read(IMAGE_APP_ID, IMAGE_SEG_HEADER, 0, &sh, IMAGE_HEADER_SIZE);
	if (len != IMAGE_HEADER_SIZE) {
		BL_WRN("app header size %u, read %u\n", IMAGE_HEADER_SIZE, len);
		return BL_INVALID_APP_ENTRY;
	}

	if (image_check_header(&sh) == IMAGE_INVALID) {
		BL_WRN("invalid app bin header\n");
		return BL_INVALID_APP_ENTRY;
	}

	if (sh.load_addr + sh.body_len > (uint32_t)__RAM_BASE) {
		BL_WRN("app overlap with bl, %#x + %#x > %p\n",
		       sh.load_addr, sh.body_len, __RAM_BASE);
	}

	len = image_read(IMAGE_APP_ID, IMAGE_SEG_BODY, 0, (void *)sh.load_addr,
	                 sh.body_len);
	if (len != sh.body_len) {
		BL_WRN("app body size %u, read %u\n", sh.body_len, len);
		return BL_INVALID_APP_ENTRY;
	}

	if (image_check_data(&sh, (void *)sh.load_addr, sh.body_len,
	                     NULL, 0) == IMAGE_INVALID) {
		BL_WRN("invalid app bin body\n");
		return BL_INVALID_APP_ENTRY;
	}

	return sh.entry;
}

#ifdef __CONFIG_IMG_COMPRESS
uint32_t flash_rw(uint32_t flash, uint32_t addr,
                  void *buf, uint32_t size, int do_write);
int flash_erase(uint32_t flash, uint32_t addr, uint32_t size);
int flash_erase_wrap(uint32_t flash, uint32_t addr, uint32_t size);

#define BL_UPDATE_DEBUG_SIZE_UNIT (50 * 1024)

#define BL_DEC_IMG_INBUF_SIZE (4 * 1024)
#define BL_DEC_IMG_OUTBUF_SIZE (16 * 1024)
#define BL_DEC_IMG_DICT_MAX   (48 * 1024)

static int bl_xz_image(image_seq_t seq)
{
	int ret = -1;
	struct xz_dec *s = NULL;
	struct xz_buf b;
	enum xz_ret xzret;
	uint8_t *in_buf = NULL, *out_buf = NULL;
	uint32_t left, read_size, offset;
	uint32_t ota_addr;
	uint32_t ota_xz_addr;
	uint32_t image_addr;
	const image_ota_param_t *iop;
	section_header_t xz_sh;
	section_header_t boot_sh;
	uint32_t len;
	uint32_t write_pos;
	uint32_t maxsize;
	uint32_t debug_size = BL_UPDATE_DEBUG_SIZE_UNIT;
/*
	uint32_t *verify_value;
	ota_verify_t verify_type;
	ota_verify_data_t verify_data;
*/
	image_cfg_t cfg;
#if BL_DBG_ON
	OS_Time_t tm;
#endif

#if BL_DBG_ON
	BL_DBG("%s() start\n", __func__);
	tm = OS_GetTicks();
#endif

	iop = image_get_ota_param();
	maxsize = iop->img_max_size;
	BL_DBG("%s, data maxsize size = 0x%x\n", __func__, maxsize);

	/* get the compressed image address */
	ota_addr = iop->ota_addr + iop->ota_size;
	ota_xz_addr = iop->ota_addr + iop->ota_size + IMAGE_HEADER_SIZE;
	BL_DBG("iop addr = 0x%x, ota addr = 0x%x, ota xz addr = 0x%x, ota info size = 0x%x\n",
			ota_addr, iop->ota_addr, ota_xz_addr, iop->ota_size);
	len = flash_rw(iop->flash[seq], ota_addr, &xz_sh, IMAGE_HEADER_SIZE, 0);
	if (len != IMAGE_HEADER_SIZE) {
		BL_ERR("%s, image read failed!\n", __func__);
		return ret;
	}
	BL_DBG("%s, ota load size = 0x%x, ota attribute = 0x%x\n", __func__,
			xz_sh.body_len, xz_sh.attribute);

	if (!(xz_sh.attribute & IMAGE_ATTR_FLAG_COMPRESS)) {
		BL_ERR("the ota image is not a compress image!\n");
		ret = -2;
		goto out;
	}

	in_buf = malloc(BL_DEC_IMG_INBUF_SIZE);
	if (in_buf == NULL) {
		BL_ERR("in_buf malloc failed\n");
		goto out;
	}

	out_buf = malloc(BL_DEC_IMG_OUTBUF_SIZE);
	if (out_buf == NULL) {
		BL_ERR("out_buf malloc failed\n");
		goto out;
	}

	BL_DBG("xz file begin...\n");
	s = xz_dec_init(XZ_DYNALLOC, BL_DEC_IMG_DICT_MAX);
	if (s == NULL) {
		BL_ERR("xz_dec_init malloc failed\n");
		goto out;
	}

	/* get boot section header */
	image_set_running_seq(0);
	len = image_read(IMAGE_BOOT_ID, IMAGE_SEG_HEADER, 0, &boot_sh, IMAGE_HEADER_SIZE);
	if (len != IMAGE_HEADER_SIZE) {
		BL_ERR("bin header size %u, read %u\n", IMAGE_HEADER_SIZE, len);
		goto out;
	}

	/* Erase the area from behind the BootLoader to IMG_MAX_SIZE */
	image_addr = boot_sh.next_addr;
	BL_DBG("erase image start, flash:%d addr:0x%x size:%d\n", iop->flash[seq],
											image_addr, iop->img_max_size);
//	if (flash_erase(iop->flash[seq], image_addr, iop->img_max_size) == -1) {
	if (flash_erase_wrap(iop->flash[seq], image_addr, iop->img_max_size) == -1) {
		BL_ERR("%s, image erase err\n", __func__);
		goto out;
	}
	BL_DBG("erase image end...\n");

	write_pos = 0;
	offset = 0;
	left = xz_sh.body_len;

	b.in = in_buf;
	b.in_pos = 0;
	b.in_size = 0;
	b.out = out_buf;
	b.out_pos = 0;
	b.out_size = BL_DEC_IMG_OUTBUF_SIZE;

	while (1) {
		if (b.in_pos == b.in_size) {
			if (left == 0) {
				BL_DBG("no more input data\n");
				break;
			}

			read_size = left > BL_DEC_IMG_INBUF_SIZE ? BL_DEC_IMG_INBUF_SIZE : left;
			len = flash_rw(iop->flash[seq], ota_xz_addr + offset, in_buf, read_size, 0);

			if (len == 0) {
				BL_ERR("flash read err\n");
				break;
			}

			offset += len;
			left -= len;
			b.in_size = len;
			b.in_pos = 0;
		}

		xzret = xz_dec_run(s, &b);
		if (xzret == XZ_OK) {

			len = flash_rw(iop->flash[seq], image_addr + write_pos, out_buf, b.out_pos, 1);
			if (len != b.out_pos) {
				BL_ERR("flash write err len:%d out_pos:%d\n", len, b.out_pos);
				break;
			}

			if (write_pos >= debug_size) {
				BL_DBG("decompress data:%dK\n", write_pos / 1024);
				debug_size += BL_UPDATE_DEBUG_SIZE_UNIT;
			}

			write_pos += b.out_pos;
			b.out_pos = 0;
			continue;
		} else if (xzret == XZ_STREAM_END) {
			len = flash_rw(iop->flash[seq], image_addr + write_pos, out_buf, b.out_pos, 1);
			if (len != b.out_pos) {
				BL_ERR("flash write err len:%d out_pos:%d\n", len, b.out_pos);
				break;
			}
			write_pos += b.out_pos;
#if BL_DBG_ON
			tm = OS_GetTicks() - tm;
			BL_DBG("%s() end, size %u --> %u, cost %u ms\n", __func__,
					 xz_sh.body_len, b.out_pos, tm);
#endif
			break;
		} else {
			BL_ERR("xz stream failed %d\n", xzret);
			break;
		}
	}

	/* check every section */
	if (image_check_sections(seq) == IMAGE_INVALID) {
		BL_ERR("ota check image failed\n");
		goto out;
	}
/*
	if (ota_get_verify_data(&verify_data) != OTA_STATUS_OK) {
		verify_type = OTA_VERIFY_NONE;
		verify_value = NULL;
	} else {
		verify_type = verify_data.ov_type;
		verify_value = (uint32_t*)(verify_data.ov_data);
	}

	if (ota_verify_image(verify_type, verify_value)  != OTA_STATUS_OK) {
		BL_ERR("ota file verify image failed\n");
		goto out;
	}
*/
	cfg.seq = 0;
	cfg.state = IMAGE_STATE_VERIFIED;
	if (image_set_cfg(&cfg) != 0)
		goto out;

	ret = 0;

out:
	if (s)
		xz_dec_end(s);
	if (in_buf)
		free(in_buf);
	if (out_buf)
		free(out_buf);
	BL_DBG("xz file end...\n");
	return ret;
}

#endif

static uint32_t bl_load_bin(void)
{
	/* init image */
	if (image_init(PRJCONF_IMG_FLASH, PRJCONF_IMG_ADDR,
	               PRJCONF_IMG_MAX_SIZE) != 0) {
		BL_ERR("img init fail\n");
		return BL_INVALID_APP_ENTRY;
	}

	const image_ota_param_t *iop = image_get_ota_param();
	if (iop->ota_addr == IMAGE_INVALID_ADDR) {
		/* ota is disable */
		image_set_running_seq(0);
		return bl_load_app_bin();
	}

	/* ota is enabled */
	uint32_t entry;
	image_cfg_t cfg;
	image_seq_t cfg_seq, load_seq, i;

	if (image_get_cfg(&cfg) == 0) {
		BL_DBG("img seq %d, state %d\n", cfg.seq, cfg.state);
		if (cfg.state == IMAGE_STATE_VERIFIED) {
			cfg_seq = cfg.seq;
		} else {
			BL_WRN("invalid img state %d, seq %d\n", cfg.state, cfg.seq);
			cfg_seq = IMAGE_SEQ_NUM; /* set to invalid sequence */
		}
	} else {
		BL_WRN("ota read cfg fail\n");
		cfg_seq = IMAGE_SEQ_NUM; /* set to invalid sequence */
	}

	/* load app bin */
	load_seq = (cfg_seq == IMAGE_SEQ_NUM) ? 0 : cfg_seq;
#ifdef __CONFIG_IMG_COMPRESS
	if (cfg_seq == 1 && cfg.state == IMAGE_STATE_VERIFIED) {
		int ret = bl_xz_image(cfg_seq);
		if (ret == 0)
			load_seq = 0;
		else if (ret == -1)
			return BL_INVALID_APP_ENTRY;
		else if (ret == -2)
			; // do nothing
	}
#endif
	for (i = 0; i < IMAGE_SEQ_NUM; ++i) {
		image_set_running_seq(load_seq);
		entry = bl_load_app_bin();
		if (entry != BL_INVALID_APP_ENTRY) {
			if (load_seq != cfg_seq) {
				BL_WRN("boot from seq %u, cfg_seq %u\n", load_seq, cfg_seq);
				cfg.seq = load_seq;
				cfg.state = IMAGE_STATE_VERIFIED;
				if (image_set_cfg(&cfg) != 0) {
					BL_ERR("write img cfg fail\n");
				}
			}
			return entry;
		} else {
			BL_WRN("load app bin fail, seq %u\n", load_seq);
			load_seq = (load_seq + 1) % IMAGE_SEQ_NUM;
		}
	}

	return BL_INVALID_APP_ENTRY;
}

int main(void)
{
	uint32_t boot_flag;
	register uint32_t entry;

	BL_DBG("start\n");

	boot_flag = HAL_PRCM_GetCPUABootFlag();
	if (boot_flag == PRCM_CPUA_BOOT_FROM_COLD_RESET) {
		bl_hw_init();
		entry = bl_load_bin();
		if (entry == BL_INVALID_APP_ENTRY) {
			BL_ERR("load app bin fail, enter upgrade mode\n");
			bl_upgrade();
		}
#ifdef __CONFIG_CHIP_XR871
		entry |= 0x1; /* set thumb bit */
#endif
		BL_DBG("goto %#x\n", entry);
		bl_hw_deinit();

		__disable_fault_irq();
		__disable_irq();
		__set_CONTROL(0); /* reset to Privileged Thread mode and use MSP */
		__DSB();
		__ISB();
		((NVIC_IRQHandler)entry)(); /* never return */
		BL_ERR("unreachable\n");
		BL_ABORT();
	} else {
		BL_ERR("boot flag %#x\n", boot_flag);
		BL_ABORT();
	}

	return -1;
}
