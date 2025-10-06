from enum import Enum


class PacketType(Enum):
    # Request Packet Types
    PING         = 0x1
    MULTIPING    = 0x2
    GETMSGSIZE   = 0x3
    GETPAGINGINFO = 0x11
    REBOOT       = 0x21
    SENDUCODE    = 0x101
    FLIPBITS     = 0x121
    APPLYUCODE   = 0x141
    READMSR      = 0x201
    APPLYUCODEEXCUTETEST = 0x151
    SENDMACHINECODE      = 0x301
    GETCORECOUNT         = 0x211
    GETLASTTESTRESULT    = 0x152
    STARTCORE            = 0x212
    GETCORESTATUS        = 0x213
    READMSRONCORE        = 0x202
    EXECUTEMACHINECODE   = 0x153
    GETIBSBUFFER         = 0x401  # Request IBS buffer from a core
    GETDSMBUFFER         = 0x501

    # Response Packet Types
    STATUS        = 0x80000000
    PONG          = 0x80000001
    MSGSIZE       = 0x80000003
    PAGINGINFO    = 0x80000011
    UCODERESPONSE = 0x80000141
    MSRRESPONSE   = 0x80000201
    UCODEEXECUTETESTRESPONSE = 0x80000151
    CORECOUNTRESPONSE        = 0x80000211
    CORESTATUSRESPONSE       = 0x80000213
    IBSBUFFER               = 0x80000401  # Response containing IBS buffer data
    DSMBUFFER               = 0x80000501
