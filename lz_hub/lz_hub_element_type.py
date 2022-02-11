from enum import IntEnum

class ELEMENT_TYPE(IntEnum):
    LZ_CORE_UPDATE          = 0x0
    UD_UPDATE               = 0x1
    CP_UPDATE               = 0x2
    APP_UPDATE              = 0x3
    CONFIG_UPDATE           = 0x4
    ALIAS_ID                = 0x5
    DEVICE_ID_REASSOC_REQ   = 0x6
    DEVICE_ID_REASSOC_RES   = 0x7
    BOOT_TICKET             = 0x8
    DEFERRAL_TICKET         = 0x9
    CMD                     = 0xA
    SENSOR_DATA             = 0xB