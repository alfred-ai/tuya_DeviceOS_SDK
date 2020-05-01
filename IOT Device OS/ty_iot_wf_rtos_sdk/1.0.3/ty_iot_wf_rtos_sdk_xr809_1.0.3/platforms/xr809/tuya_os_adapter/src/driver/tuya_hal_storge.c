/***********************************************************
*  File: tuya_hal_storge.c 
*  Author: nzy
*  Date: 20170920
***********************************************************/
#include "tuya_hal_storge.h"
#include "../errors_compat.h"

#include "driver/chip/flashchip/flash_chip.h"
#include "driver/chip/hal_flash.h"

/***********************************************************
*************************micro define***********************
***********************************************************/
#define PARTITION_SIZE               FLASH_ERASE_4KB  /* 4KB */
#define FLH_BLOCK_SZ                 PARTITION_SIZE

// flash map
#define SIMPLE_FLASH_START          (0x200000 - 0x10000 - 0x4000)
#define SIMPLE_FLASH_SIZE            0x10000 // 64k

#define SIMPLE_FLASH_SWAP_START     (0x200000 - 0x4000)
#define SIMPLE_FLASH_SWAP_SIZE       0x4000 // 16k

#define SIMPLE_FLASH_KEY_ADDR       (0x200000 - 0x10000 - 0x4000 - 0x1000)

#define MFLASH                       0
#define FLASH_OPEN_TIMEOUT          (5000)

#define SYSINFO_ADDR                (0x107000)

/***********************************************************
*************************variable define********************
***********************************************************/
static UNI_STORAGE_DESC_S storage = {
    SIMPLE_FLASH_START,
    SIMPLE_FLASH_SIZE,
    FLH_BLOCK_SZ,
    SIMPLE_FLASH_SWAP_START,
    SIMPLE_FLASH_SWAP_SIZE,
    SIMPLE_FLASH_KEY_ADDR
};

static UF_PARTITION_TABLE_S uf_file = {
    .sector_size          = PARTITION_SIZE,
    .uf_partition_num     = 2,
    .uf_partition         = {
     {SIMPLE_FLASH_KEY_ADDR - 0x8000, 0x8000},
     {SYSINFO_ADDR-0x8000, 0x8000},
     }
};

/***********************************************************
*************************function define********************
***********************************************************/
/***********************************************************
*  Function: tuya_hal_flash_read
*  Input: addr size
*  Output: dst
*  Return: none
***********************************************************/
int tuya_hal_flash_read(const uint32_t addr, uint8_t *dst, const uint32_t size)
{
    HAL_Status status;

    if(NULL == dst) {
        return OPRT_INVALID_PARM;
    }

    status = HAL_Flash_Open(MFLASH, FLASH_OPEN_TIMEOUT);
    if (status != HAL_OK) {
        return OPRT_COM_ERROR;
    }

    status = HAL_Flash_Read(MFLASH, addr, dst, size);
    HAL_Flash_Close(MFLASH);
    if (status != HAL_OK) {
        return OPRT_WR_FLASH_ERROR;
    }
    return OPRT_OK;
}


/***********************************************************
*  Function: uni_flash_write
*  Input: addr src size
*  Output: none
*  Return: none
***********************************************************/
int tuya_hal_flash_write(const uint32_t addr, const uint8_t *src, const uint32_t size)
{
    HAL_Status status;

    if(NULL == src) {
        return OPRT_INVALID_PARM;
    }

    status = HAL_Flash_Open(MFLASH, FLASH_OPEN_TIMEOUT);
    if (status != HAL_OK) {
        return OPRT_COM_ERROR;
    }

    status = HAL_Flash_Write(MFLASH, addr, src, size);
    HAL_Flash_Close(MFLASH);
    if (status != HAL_OK) {
        return OPRT_WR_FLASH_ERROR;
    }

    return OPRT_OK;
}


/***********************************************************
*  Function: tuya_hal_flash_erase
*  Input: addr size
*  Output:
*  Return: none
***********************************************************/
int tuya_hal_flash_erase(const uint32_t addr, const uint32_t size)
{
    HAL_Status status;
    uint32_t addr_start;
    FlashEraseMode size_type;
    uint16_t block_cnt;

    size_type = FLASH_ERASE_4KB;
    block_cnt = size / size_type;

    status = HAL_Flash_Open(MFLASH, FLASH_OPEN_TIMEOUT);
    if (status != HAL_OK) {
        return OPRT_COM_ERROR;
    }

    HAL_Flash_MemoryOf(MFLASH, size_type, addr, &addr_start);
    status = HAL_Flash_Erase(MFLASH, size_type, addr_start, block_cnt);
    HAL_Flash_Close(MFLASH);
    if (status != HAL_OK) {
        return OPRT_WR_FLASH_ERROR;
    }
    
    return OPRT_OK;
}

/***********************************************************
*  Function: tuya_hal_uf_get_desc
*  Input: none
*  Output: none
*  Return: UF_PARTITION_TABLE_S
***********************************************************/
UF_PARTITION_TABLE_S *tuya_hal_uf_get_desc(void)
{
    return &uf_file;
}

/***********************************************************
*  Function: tuya_hal_storage_get_desc
*  Input: none
*  Output: none
*  Return: UNI_STORGE_DESC_S
***********************************************************/
UNI_STORAGE_DESC_S *tuya_hal_storage_get_desc(void)
{
    return &storage;
}
