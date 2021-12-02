from enum import IntEnum

class ELEMENT_TYPE(IntEnum):
    LZ_CORE_UPDATE          = 0x0
    UD_UPDATE               = 0x1
    UM_UPDATE               = 0x2
    APP_UPDATE              = 0x3
    CERTS_UPDATE            = 0x4
    CONFIG_UPDATE           = 0x5
    ALIAS_ID                = 0x6
    DEVICE_ID_REASSOC_REQ   = 0x7
    CERTS_UPDATE_REQ        = 0x8
    BOOT_TICKET             = 0x9
    DEFERRAL_TICKET         = 0xA
    CMD                     = 0xB
    SENSOR_DATA             = 0xC