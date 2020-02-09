/*
 * QEMU e1000 emulation
 * Software developer's manual:
 * http://download.intel.com/design/network/manuals/8254x_GBe_SDM.pdf
 */
#include "hw.h"
#include "pci.h"
#include "net.h"
//#include "net/checksum.h"
#include "loader.h"
#include "sysemu.h"
#include "dma.h"

/* Structures, enums, and macros for the MAC */
/* PCI Device IDs */
#define E1000_DEV_ID_82542               0x1000
#define E1000_DEV_ID_82543GC_FIBER       0x1001
#define E1000_DEV_ID_82543GC_COPPER      0x1004
#define E1000_DEV_ID_82544EI_COPPER      0x1008
#define E1000_DEV_ID_82544EI_FIBER       0x1009
#define E1000_DEV_ID_82544GC_COPPER      0x100C
#define E1000_DEV_ID_82544GC_LOM         0x100D
#define E1000_DEV_ID_82540EM             0x100E
#define E1000_DEV_ID_82540EM_LOM         0x1015
#define E1000_DEV_ID_82540EP_LOM         0x1016
#define E1000_DEV_ID_82540EP             0x1017
#define E1000_DEV_ID_82540EP_LP          0x101E
#define E1000_DEV_ID_82545EM_COPPER      0x100F
#define E1000_DEV_ID_82545EM_FIBER       0x1011
#define E1000_DEV_ID_82545GM_COPPER      0x1026
#define E1000_DEV_ID_82545GM_FIBER       0x1027
#define E1000_DEV_ID_82545GM_SERDES      0x1028
#define E1000_DEV_ID_82546EB_COPPER      0x1010
#define E1000_DEV_ID_82546EB_FIBER       0x1012
#define E1000_DEV_ID_82546EB_QUAD_COPPER 0x101D
#define E1000_DEV_ID_82541EI             0x1013
#define E1000_DEV_ID_82541EI_MOBILE      0x1018
#define E1000_DEV_ID_82541ER_LOM         0x1014
#define E1000_DEV_ID_82541ER             0x1078
#define E1000_DEV_ID_82547GI             0x1075
#define E1000_DEV_ID_82541GI             0x1076
#define E1000_DEV_ID_82541GI_MOBILE      0x1077
#define E1000_DEV_ID_82541GI_LF          0x107C
#define E1000_DEV_ID_82546GB_COPPER      0x1079
#define E1000_DEV_ID_82546GB_FIBER       0x107A
#define E1000_DEV_ID_82546GB_SERDES      0x107B
#define E1000_DEV_ID_82546GB_PCIE        0x108A
#define E1000_DEV_ID_82546GB_QUAD_COPPER 0x1099
#define E1000_DEV_ID_82547EI             0x1019
#define E1000_DEV_ID_82547EI_MOBILE      0x101A
#define E1000_DEV_ID_82571EB_COPPER      0x105E
#define E1000_DEV_ID_82571EB_FIBER       0x105F
#define E1000_DEV_ID_82571EB_SERDES      0x1060
#define E1000_DEV_ID_82571EB_QUAD_COPPER 0x10A4
#define E1000_DEV_ID_82571PT_QUAD_COPPER 0x10D5
#define E1000_DEV_ID_82571EB_QUAD_FIBER  0x10A5
#define E1000_DEV_ID_82571EB_QUAD_COPPER_LOWPROFILE  0x10BC
#define E1000_DEV_ID_82571EB_SERDES_DUAL 0x10D9
#define E1000_DEV_ID_82571EB_SERDES_QUAD 0x10DA
#define E1000_DEV_ID_82572EI_COPPER      0x107D
#define E1000_DEV_ID_82572EI_FIBER       0x107E
#define E1000_DEV_ID_82572EI_SERDES      0x107F
#define E1000_DEV_ID_82572EI             0x10B9
#define E1000_DEV_ID_82573E              0x108B
#define E1000_DEV_ID_82573E_IAMT         0x108C
#define E1000_DEV_ID_82573L              0x109A
#define E1000_DEV_ID_82546GB_QUAD_COPPER_KSP3 0x10B5
#define E1000_DEV_ID_80003ES2LAN_COPPER_DPT     0x1096
#define E1000_DEV_ID_80003ES2LAN_SERDES_DPT     0x1098
#define E1000_DEV_ID_80003ES2LAN_COPPER_SPT     0x10BA
#define E1000_DEV_ID_80003ES2LAN_SERDES_SPT     0x10BB

#define E1000_DEV_ID_ICH8_IGP_M_AMT      0x1049
#define E1000_DEV_ID_ICH8_IGP_AMT        0x104A
#define E1000_DEV_ID_ICH8_IGP_C          0x104B
#define E1000_DEV_ID_ICH8_IFE            0x104C
#define E1000_DEV_ID_ICH8_IFE_GT         0x10C4
#define E1000_DEV_ID_ICH8_IFE_G          0x10C5
#define E1000_DEV_ID_ICH8_IGP_M          0x104D

/* Register Set. (82543, 82544)
 *
 * Registers are defined to be 32 bits and  should be accessed as 32 bit values.
 * These registers are physically located on the NIC, but are mapped into the
 * host memory address space.
 *
 * RW - register is both readable and writable
 * RO - register is read only
 * WO - register is write only
 * R/clr - register is read only and is cleared when read
 * A - register array
 */
#define E1000_CTRL     0x00000  /* Device Control - RW */
#define E1000_CTRL_DUP 0x00004  /* Device Control Duplicate (Shadow) - RW */
#define E1000_STATUS   0x00008  /* Device Status - RO */
#define E1000_EECD     0x00010  /* EEPROM/Flash Control - RW */
#define E1000_EERD     0x00014  /* EEPROM Read - RW */
#define E1000_CTRL_EXT 0x00018  /* Extended Device Control - RW */
#define E1000_FLA      0x0001C  /* Flash Access - RW */
#define E1000_MDIC     0x00020  /* MDI Control - RW */
#define E1000_SCTL     0x00024  /* SerDes Control - RW */
#define E1000_FEXTNVM  0x00028  /* Future Extended NVM register */
#define E1000_FCAL     0x00028  /* Flow Control Address Low - RW */
#define E1000_FCAH     0x0002C  /* Flow Control Address High -RW */
#define E1000_FCT      0x00030  /* Flow Control Type - RW */
#define E1000_VET      0x00038  /* VLAN Ether Type - RW */
#define E1000_ICR      0x000C0  /* Interrupt Cause Read - R/clr */
#define E1000_ITR      0x000C4  /* Interrupt Throttling Rate - RW */
#define E1000_ICS      0x000C8  /* Interrupt Cause Set - WO */
#define E1000_IMS      0x000D0  /* Interrupt Mask Set - RW */
#define E1000_IMC      0x000D8  /* Interrupt Mask Clear - WO */
#define E1000_IAM      0x000E0  /* Interrupt Acknowledge Auto Mask */
#define E1000_RCTL     0x00100  /* RX Control - RW */
#define E1000_RDTR1    0x02820  /* RX Delay Timer (1) - RW */
#define E1000_RDBAL1   0x02900  /* RX Descriptor Base Address Low (1) - RW */
#define E1000_RDBAH1   0x02904  /* RX Descriptor Base Address High (1) - RW */
#define E1000_RDLEN1   0x02908  /* RX Descriptor Length (1) - RW */
#define E1000_RDH1     0x02910  /* RX Descriptor Head (1) - RW */
#define E1000_RDT1     0x02918  /* RX Descriptor Tail (1) - RW */
#define E1000_FCTTV    0x00170  /* Flow Control Transmit Timer Value - RW */
#define E1000_TXCW     0x00178  /* TX Configuration Word - RW */
#define E1000_RXCW     0x00180  /* RX Configuration Word - RO */
#define E1000_TCTL     0x00400  /* TX Control - RW */
#define E1000_TCTL_EXT 0x00404  /* Extended TX Control - RW */
#define E1000_TIPG     0x00410  /* TX Inter-packet gap -RW */
#define E1000_TBT      0x00448  /* TX Burst Timer - RW */
#define E1000_AIT      0x00458  /* Adaptive Interframe Spacing Throttle - RW */
#define E1000_LEDCTL   0x00E00  /* LED Control - RW */
#define E1000_EXTCNF_CTRL  0x00F00  /* Extended Configuration Control */
#define E1000_EXTCNF_SIZE  0x00F08  /* Extended Configuration Size */
#define E1000_PHY_CTRL     0x00F10  /* PHY Control Register in CSR */
#define FEXTNVM_SW_CONFIG  0x0001
#define E1000_PBA      0x01000  /* Packet Buffer Allocation - RW */
#define E1000_PBS      0x01008  /* Packet Buffer Size */
#define E1000_EEMNGCTL 0x01010  /* MNG EEprom Control */
#define E1000_FLASH_UPDATES 1000
#define E1000_EEARBC   0x01024  /* EEPROM Auto Read Bus Control */
#define E1000_FLASHT   0x01028  /* FLASH Timer Register */
#define E1000_EEWR     0x0102C  /* EEPROM Write Register - RW */
#define E1000_FLSWCTL  0x01030  /* FLASH control register */
#define E1000_FLSWDATA 0x01034  /* FLASH data register */
#define E1000_FLSWCNT  0x01038  /* FLASH Access Counter */
#define E1000_FLOP     0x0103C  /* FLASH Opcode Register */
#define E1000_ERT      0x02008  /* Early Rx Threshold - RW */
#define E1000_FCRTL    0x02160  /* Flow Control Receive Threshold Low - RW */
#define E1000_FCRTH    0x02168  /* Flow Control Receive Threshold High - RW */
#define E1000_PSRCTL   0x02170  /* Packet Split Receive Control - RW */
#define E1000_RDBAL    0x02800  /* RX Descriptor Base Address Low - RW */
#define E1000_RDBAH    0x02804  /* RX Descriptor Base Address High - RW */
#define E1000_RDLEN    0x02808  /* RX Descriptor Length - RW */
#define E1000_RDH      0x02810  /* RX Descriptor Head - RW */
#define E1000_RDT      0x02818  /* RX Descriptor Tail - RW */
#define E1000_RDTR     0x02820  /* RX Delay Timer - RW */
#define E1000_RDBAL0   E1000_RDBAL /* RX Desc Base Address Low (0) - RW */
#define E1000_RDBAH0   E1000_RDBAH /* RX Desc Base Address High (0) - RW */
#define E1000_RDLEN0   E1000_RDLEN /* RX Desc Length (0) - RW */
#define E1000_RDH0     E1000_RDH   /* RX Desc Head (0) - RW */
#define E1000_RDT0     E1000_RDT   /* RX Desc Tail (0) - RW */
#define E1000_RDTR0    E1000_RDTR  /* RX Delay Timer (0) - RW */
#define E1000_RXDCTL   0x02828  /* RX Descriptor Control queue 0 - RW */
#define E1000_RXDCTL1  0x02928  /* RX Descriptor Control queue 1 - RW */
#define E1000_RADV     0x0282C  /* RX Interrupt Absolute Delay Timer - RW */
#define E1000_RSRPD    0x02C00  /* RX Small Packet Detect - RW */
#define E1000_RAID     0x02C08  /* Receive Ack Interrupt Delay - RW */
#define E1000_TXDMAC   0x03000  /* TX DMA Control - RW */
#define E1000_KABGTXD  0x03004  /* AFE Band Gap Transmit Ref Data */
#define E1000_TDFH     0x03410  /* TX Data FIFO Head - RW */
#define E1000_TDFT     0x03418  /* TX Data FIFO Tail - RW */
#define E1000_TDFHS    0x03420  /* TX Data FIFO Head Saved - RW */
#define E1000_TDFTS    0x03428  /* TX Data FIFO Tail Saved - RW */
#define E1000_TDFPC    0x03430  /* TX Data FIFO Packet Count - RW */
#define E1000_TDBAL    0x03800  /* TX Descriptor Base Address Low - RW */
#define E1000_TDBAH    0x03804  /* TX Descriptor Base Address High - RW */
#define E1000_TDLEN    0x03808  /* TX Descriptor Length - RW */
#define E1000_TDH      0x03810  /* TX Descriptor Head - RW */
#define E1000_TDT      0x03818  /* TX Descripotr Tail - RW */
#define E1000_TIDV     0x03820  /* TX Interrupt Delay Value - RW */
#define E1000_TXDCTL   0x03828  /* TX Descriptor Control - RW */
#define E1000_TADV     0x0382C  /* TX Interrupt Absolute Delay Val - RW */
#define E1000_TSPMT    0x03830  /* TCP Segmentation PAD & Min Threshold - RW */
#define E1000_TARC0    0x03840  /* TX Arbitration Count (0) */
#define E1000_TDBAL1   0x03900  /* TX Desc Base Address Low (1) - RW */
#define E1000_TDBAH1   0x03904  /* TX Desc Base Address High (1) - RW */
#define E1000_TDLEN1   0x03908  /* TX Desc Length (1) - RW */
#define E1000_TDH1     0x03910  /* TX Desc Head (1) - RW */
#define E1000_TDT1     0x03918  /* TX Desc Tail (1) - RW */
#define E1000_TXDCTL1  0x03928  /* TX Descriptor Control (1) - RW */
#define E1000_TARC1    0x03940  /* TX Arbitration Count (1) */
#define E1000_CRCERRS  0x04000  /* CRC Error Count - R/clr */
#define E1000_ALGNERRC 0x04004  /* Alignment Error Count - R/clr */
#define E1000_SYMERRS  0x04008  /* Symbol Error Count - R/clr */
#define E1000_RXERRC   0x0400C  /* Receive Error Count - R/clr */
#define E1000_MPC      0x04010  /* Missed Packet Count - R/clr */
#define E1000_SCC      0x04014  /* Single Collision Count - R/clr */
#define E1000_ECOL     0x04018  /* Excessive Collision Count - R/clr */
#define E1000_MCC      0x0401C  /* Multiple Collision Count - R/clr */
#define E1000_LATECOL  0x04020  /* Late Collision Count - R/clr */
#define E1000_COLC     0x04028  /* Collision Count - R/clr */
#define E1000_DC       0x04030  /* Defer Count - R/clr */
#define E1000_TNCRS    0x04034  /* TX-No CRS - R/clr */
#define E1000_SEC      0x04038  /* Sequence Error Count - R/clr */
#define E1000_CEXTERR  0x0403C  /* Carrier Extension Error Count - R/clr */
#define E1000_RLEC     0x04040  /* Receive Length Error Count - R/clr */
#define E1000_XONRXC   0x04048  /* XON RX Count - R/clr */
#define E1000_XONTXC   0x0404C  /* XON TX Count - R/clr */
#define E1000_XOFFRXC  0x04050  /* XOFF RX Count - R/clr */
#define E1000_XOFFTXC  0x04054  /* XOFF TX Count - R/clr */
#define E1000_FCRUC    0x04058  /* Flow Control RX Unsupported Count- R/clr */
#define E1000_PRC64    0x0405C  /* Packets RX (64 bytes) - R/clr */
#define E1000_PRC127   0x04060  /* Packets RX (65-127 bytes) - R/clr */
#define E1000_PRC255   0x04064  /* Packets RX (128-255 bytes) - R/clr */
#define E1000_PRC511   0x04068  /* Packets RX (255-511 bytes) - R/clr */
#define E1000_PRC1023  0x0406C  /* Packets RX (512-1023 bytes) - R/clr */
#define E1000_PRC1522  0x04070  /* Packets RX (1024-1522 bytes) - R/clr */
#define E1000_GPRC     0x04074  /* Good Packets RX Count - R/clr */
#define E1000_BPRC     0x04078  /* Broadcast Packets RX Count - R/clr */
#define E1000_MPRC     0x0407C  /* Multicast Packets RX Count - R/clr */
#define E1000_GPTC     0x04080  /* Good Packets TX Count - R/clr */
#define E1000_GORCL    0x04088  /* Good Octets RX Count Low - R/clr */
#define E1000_GORCH    0x0408C  /* Good Octets RX Count High - R/clr */
#define E1000_GOTCL    0x04090  /* Good Octets TX Count Low - R/clr */
#define E1000_GOTCH    0x04094  /* Good Octets TX Count High - R/clr */
#define E1000_RNBC     0x040A0  /* RX No Buffers Count - R/clr */
#define E1000_RUC      0x040A4  /* RX Undersize Count - R/clr */
#define E1000_RFC      0x040A8  /* RX Fragment Count - R/clr */
#define E1000_ROC      0x040AC  /* RX Oversize Count - R/clr */
#define E1000_RJC      0x040B0  /* RX Jabber Count - R/clr */
#define E1000_MGTPRC   0x040B4  /* Management Packets RX Count - R/clr */
#define E1000_MGTPDC   0x040B8  /* Management Packets Dropped Count - R/clr */
#define E1000_MGTPTC   0x040BC  /* Management Packets TX Count - R/clr */
#define E1000_TORL     0x040C0  /* Total Octets RX Low - R/clr */
#define E1000_TORH     0x040C4  /* Total Octets RX High - R/clr */
#define E1000_TOTL     0x040C8  /* Total Octets TX Low - R/clr */
#define E1000_TOTH     0x040CC  /* Total Octets TX High - R/clr */
#define E1000_TPR      0x040D0  /* Total Packets RX - R/clr */
#define E1000_TPT      0x040D4  /* Total Packets TX - R/clr */
#define E1000_PTC64    0x040D8  /* Packets TX (64 bytes) - R/clr */
#define E1000_PTC127   0x040DC  /* Packets TX (65-127 bytes) - R/clr */
#define E1000_PTC255   0x040E0  /* Packets TX (128-255 bytes) - R/clr */
#define E1000_PTC511   0x040E4  /* Packets TX (256-511 bytes) - R/clr */
#define E1000_PTC1023  0x040E8  /* Packets TX (512-1023 bytes) - R/clr */
#define E1000_PTC1522  0x040EC  /* Packets TX (1024-1522 Bytes) - R/clr */
#define E1000_MPTC     0x040F0  /* Multicast Packets TX Count - R/clr */
#define E1000_BPTC     0x040F4  /* Broadcast Packets TX Count - R/clr */
#define E1000_TSCTC    0x040F8  /* TCP Segmentation Context TX - R/clr */
#define E1000_TSCTFC   0x040FC  /* TCP Segmentation Context TX Fail - R/clr */
#define E1000_IAC      0x04100  /* Interrupt Assertion Count */
#define E1000_ICRXPTC  0x04104  /* Interrupt Cause Rx Packet Timer Expire Count */
#define E1000_ICRXATC  0x04108  /* Interrupt Cause Rx Absolute Timer Expire Count */
#define E1000_ICTXPTC  0x0410C  /* Interrupt Cause Tx Packet Timer Expire Count */
#define E1000_ICTXATC  0x04110  /* Interrupt Cause Tx Absolute Timer Expire Count */
#define E1000_ICTXQEC  0x04118  /* Interrupt Cause Tx Queue Empty Count */
#define E1000_ICTXQMTC 0x0411C  /* Interrupt Cause Tx Queue Minimum Threshold Count */
#define E1000_ICRXDMTC 0x04120  /* Interrupt Cause Rx Descriptor Minimum Threshold Count */
#define E1000_ICRXOC   0x04124  /* Interrupt Cause Receiver Overrun Count */
#define E1000_RXCSUM   0x05000  /* RX Checksum Control - RW */
#define E1000_RFCTL    0x05008  /* Receive Filter Control*/
#define E1000_MTA      0x05200  /* Multicast Table Array - RW Array */
#define E1000_RA       0x05400  /* Receive Address - RW Array */
#define E1000_VFTA     0x05600  /* VLAN Filter Table Array - RW Array */
#define E1000_WUC      0x05800  /* Wakeup Control - RW */
#define E1000_WUFC     0x05808  /* Wakeup Filter Control - RW */
#define E1000_WUS      0x05810  /* Wakeup Status - RO */
#define E1000_MANC     0x05820  /* Management Control - RW */
#define E1000_IPAV     0x05838  /* IP Address Valid - RW */
#define E1000_IP4AT    0x05840  /* IPv4 Address Table - RW Array */
#define E1000_IP6AT    0x05880  /* IPv6 Address Table - RW Array */
#define E1000_WUPL     0x05900  /* Wakeup Packet Length - RW */
#define E1000_WUPM     0x05A00  /* Wakeup Packet Memory - RO A */
#define E1000_FFLT     0x05F00  /* Flexible Filter Length Table - RW Array */
#define E1000_HOST_IF  0x08800  /* Host Interface */
#define E1000_FFMT     0x09000  /* Flexible Filter Mask Table - RW Array */
#define E1000_FFVT     0x09800  /* Flexible Filter Value Table - RW Array */

#define E1000_KUMCTRLSTA 0x00034 /* MAC-PHY interface - RW */
#define E1000_MDPHYA     0x0003C  /* PHY address - RW */
#define E1000_MANC2H     0x05860  /* Managment Control To Host - RW */
#define E1000_SW_FW_SYNC 0x05B5C /* Software-Firmware Synchronization - RW */

#define E1000_GCR       0x05B00 /* PCI-Ex Control */
#define E1000_GSCL_1    0x05B10 /* PCI-Ex Statistic Control #1 */
#define E1000_GSCL_2    0x05B14 /* PCI-Ex Statistic Control #2 */
#define E1000_GSCL_3    0x05B18 /* PCI-Ex Statistic Control #3 */
#define E1000_GSCL_4    0x05B1C /* PCI-Ex Statistic Control #4 */
#define E1000_FACTPS    0x05B30 /* Function Active and Power State to MNG */
#define E1000_SWSM      0x05B50 /* SW Semaphore */
#define E1000_FWSM      0x05B54 /* FW Semaphore */
#define E1000_FFLT_DBG  0x05F04 /* Debug Register */
#define E1000_HICR      0x08F00 /* Host Inteface Control */

/* RSS registers */
#define E1000_CPUVEC    0x02C10 /* CPU Vector Register - RW */
#define E1000_MRQC      0x05818 /* Multiple Receive Control - RW */
#define E1000_RETA      0x05C00 /* Redirection Table - RW Array */
#define E1000_RSSRK     0x05C80 /* RSS Random Key - RW Array */
#define E1000_RSSIM     0x05864 /* RSS Interrupt Mask */
#define E1000_RSSIR     0x05868 /* RSS Interrupt Request */

/* PHY 1000 MII Register/Bit Definitions */
/* PHY Registers defined by IEEE */
#define PHY_CTRL         0x00 /* Control Register */
#define PHY_STATUS       0x01 /* Status Regiser */
#define PHY_ID1          0x02 /* Phy Id Reg (word 1) */
#define PHY_ID2          0x03 /* Phy Id Reg (word 2) */
#define PHY_AUTONEG_ADV  0x04 /* Autoneg Advertisement */
#define PHY_LP_ABILITY   0x05 /* Link Partner Ability (Base Page) */
#define PHY_AUTONEG_EXP  0x06 /* Autoneg Expansion Reg */
#define PHY_NEXT_PAGE_TX 0x07 /* Next Page TX */
#define PHY_LP_NEXT_PAGE 0x08 /* Link Partner Next Page */
#define PHY_1000T_CTRL   0x09 /* 1000Base-T Control Reg */
#define PHY_1000T_STATUS 0x0A /* 1000Base-T Status Reg */
#define PHY_EXT_STATUS   0x0F /* Extended Status Reg */

#define MAX_PHY_REG_ADDRESS        0x1F  /* 5 bit address bus (0-0x1F) */
#define MAX_PHY_MULTI_PAGE_REG     0xF   /* Registers equal on all pages */

/* M88E1000 Specific Registers */
#define M88E1000_PHY_SPEC_CTRL     0x10  /* PHY Specific Control Register */
#define M88E1000_PHY_SPEC_STATUS   0x11  /* PHY Specific Status Register */
#define M88E1000_INT_ENABLE        0x12  /* Interrupt Enable Register */
#define M88E1000_INT_STATUS        0x13  /* Interrupt Status Register */
#define M88E1000_EXT_PHY_SPEC_CTRL 0x14  /* Extended PHY Specific Control */
#define M88E1000_RX_ERR_CNTR       0x15  /* Receive Error Counter */

#define M88E1000_PHY_EXT_CTRL      0x1A  /* PHY extend control register */
#define M88E1000_PHY_PAGE_SELECT   0x1D  /* Reg 29 for page number setting */
#define M88E1000_PHY_GEN_CONTROL   0x1E  /* Its meaning depends on reg 29 */
#define M88E1000_PHY_VCO_REG_BIT8  0x100 /* Bits 8 & 11 are adjusted for */
#define M88E1000_PHY_VCO_REG_BIT11 0x800    /* improved BER performance */

/* PHY Status Register */
#define MII_SR_EXTENDED_CAPS     0x0001	/* Extended register capabilities */
#define MII_SR_JABBER_DETECT     0x0002	/* Jabber Detected */
#define MII_SR_LINK_STATUS       0x0004	/* Link Status 1 = link */
#define MII_SR_AUTONEG_CAPS      0x0008	/* Auto Neg Capable */
#define MII_SR_REMOTE_FAULT      0x0010	/* Remote Fault Detect */
#define MII_SR_AUTONEG_COMPLETE  0x0020	/* Auto Neg Complete */
#define MII_SR_PREAMBLE_SUPPRESS 0x0040	/* Preamble may be suppressed */
#define MII_SR_EXTENDED_STATUS   0x0100	/* Ext. status info in Reg 0x0F */
#define MII_SR_100T2_HD_CAPS     0x0200	/* 100T2 Half Duplex Capable */
#define MII_SR_100T2_FD_CAPS     0x0400	/* 100T2 Full Duplex Capable */
#define MII_SR_10T_HD_CAPS       0x0800	/* 10T   Half Duplex Capable */
#define MII_SR_10T_FD_CAPS       0x1000	/* 10T   Full Duplex Capable */
#define MII_SR_100X_HD_CAPS      0x2000	/* 100X  Half Duplex Capable */
#define MII_SR_100X_FD_CAPS      0x4000	/* 100X  Full Duplex Capable */
#define MII_SR_100T4_CAPS        0x8000	/* 100T4 Capable */

/* Interrupt Cause Read */
#define E1000_ICR_TXDW          0x00000001 /* Transmit desc written back */
#define E1000_ICR_TXQE          0x00000002 /* Transmit Queue empty */
#define E1000_ICR_LSC           0x00000004 /* Link Status Change */
#define E1000_ICR_RXSEQ         0x00000008 /* rx sequence error */
#define E1000_ICR_RXDMT0        0x00000010 /* rx desc min. threshold (0) */
#define E1000_ICR_RXO           0x00000040 /* rx overrun */
#define E1000_ICR_RXT0          0x00000080 /* rx timer intr (ring 0) */
#define E1000_ICR_MDAC          0x00000200 /* MDIO access complete */
#define E1000_ICR_RXCFG         0x00000400 /* RX /c/ ordered set */
#define E1000_ICR_GPI_EN0       0x00000800 /* GP Int 0 */
#define E1000_ICR_GPI_EN1       0x00001000 /* GP Int 1 */
#define E1000_ICR_GPI_EN2       0x00002000 /* GP Int 2 */
#define E1000_ICR_GPI_EN3       0x00004000 /* GP Int 3 */
#define E1000_ICR_TXD_LOW       0x00008000
#define E1000_ICR_SRPD          0x00010000
#define E1000_ICR_ACK           0x00020000 /* Receive Ack frame */
#define E1000_ICR_MNG           0x00040000 /* Manageability event */
#define E1000_ICR_DOCK          0x00080000 /* Dock/Undock */
#define E1000_ICR_INT_ASSERTED  0x80000000 /* If this bit asserted, the driver should claim the interrupt */
#define E1000_ICR_RXD_FIFO_PAR0 0x00100000 /* queue 0 Rx descriptor FIFO parity error */
#define E1000_ICR_TXD_FIFO_PAR0 0x00200000 /* queue 0 Tx descriptor FIFO parity error */
#define E1000_ICR_HOST_ARB_PAR  0x00400000 /* host arb read buffer parity error */
#define E1000_ICR_PB_PAR        0x00800000 /* packet buffer parity error */
#define E1000_ICR_RXD_FIFO_PAR1 0x01000000 /* queue 1 Rx descriptor FIFO parity error */
#define E1000_ICR_TXD_FIFO_PAR1 0x02000000 /* queue 1 Tx descriptor FIFO parity error */
#define E1000_ICR_ALL_PARITY    0x03F00000 /* all parity error bits */
#define E1000_ICR_DSW           0x00000020 /* FW changed the status of DISSW bit in the FWSM */
#define E1000_ICR_PHYINT        0x00001000 /* LAN connected device generates an interrupt */
#define E1000_ICR_EPRST         0x00100000 /* ME handware reset occurs */

/* Interrupt Cause Set */
#define E1000_ICS_TXDW      E1000_ICR_TXDW      /* Transmit desc written back */
#define E1000_ICS_TXQE      E1000_ICR_TXQE      /* Transmit Queue empty */
#define E1000_ICS_LSC       E1000_ICR_LSC       /* Link Status Change */
#define E1000_ICS_RXSEQ     E1000_ICR_RXSEQ     /* rx sequence error */
#define E1000_ICS_RXDMT0    E1000_ICR_RXDMT0    /* rx desc min. threshold */
#define E1000_ICS_RXO       E1000_ICR_RXO       /* rx overrun */
#define E1000_ICS_RXT0      E1000_ICR_RXT0      /* rx timer intr */
#define E1000_ICS_MDAC      E1000_ICR_MDAC      /* MDIO access complete */
#define E1000_ICS_RXCFG     E1000_ICR_RXCFG     /* RX /c/ ordered set */
#define E1000_ICS_GPI_EN0   E1000_ICR_GPI_EN0   /* GP Int 0 */
#define E1000_ICS_GPI_EN1   E1000_ICR_GPI_EN1   /* GP Int 1 */
#define E1000_ICS_GPI_EN2   E1000_ICR_GPI_EN2   /* GP Int 2 */
#define E1000_ICS_GPI_EN3   E1000_ICR_GPI_EN3   /* GP Int 3 */
#define E1000_ICS_TXD_LOW   E1000_ICR_TXD_LOW
#define E1000_ICS_SRPD      E1000_ICR_SRPD
#define E1000_ICS_ACK       E1000_ICR_ACK       /* Receive Ack frame */
#define E1000_ICS_MNG       E1000_ICR_MNG       /* Manageability event */
#define E1000_ICS_DOCK      E1000_ICR_DOCK      /* Dock/Undock */
#define E1000_ICS_RXD_FIFO_PAR0 E1000_ICR_RXD_FIFO_PAR0 /* queue 0 Rx descriptor FIFO parity error */
#define E1000_ICS_TXD_FIFO_PAR0 E1000_ICR_TXD_FIFO_PAR0 /* queue 0 Tx descriptor FIFO parity error */
#define E1000_ICS_HOST_ARB_PAR  E1000_ICR_HOST_ARB_PAR  /* host arb read buffer parity error */
#define E1000_ICS_PB_PAR        E1000_ICR_PB_PAR        /* packet buffer parity error */
#define E1000_ICS_RXD_FIFO_PAR1 E1000_ICR_RXD_FIFO_PAR1 /* queue 1 Rx descriptor FIFO parity error */
#define E1000_ICS_TXD_FIFO_PAR1 E1000_ICR_TXD_FIFO_PAR1 /* queue 1 Tx descriptor FIFO parity error */
#define E1000_ICS_DSW       E1000_ICR_DSW
#define E1000_ICS_PHYINT    E1000_ICR_PHYINT
#define E1000_ICS_EPRST     E1000_ICR_EPRST

/* Interrupt Mask Set */
#define E1000_IMS_TXDW      E1000_ICR_TXDW      /* Transmit desc written back */
#define E1000_IMS_TXQE      E1000_ICR_TXQE      /* Transmit Queue empty */
#define E1000_IMS_LSC       E1000_ICR_LSC       /* Link Status Change */
#define E1000_IMS_RXSEQ     E1000_ICR_RXSEQ     /* rx sequence error */
#define E1000_IMS_RXDMT0    E1000_ICR_RXDMT0    /* rx desc min. threshold */
#define E1000_IMS_RXO       E1000_ICR_RXO       /* rx overrun */
#define E1000_IMS_RXT0      E1000_ICR_RXT0      /* rx timer intr */
#define E1000_IMS_MDAC      E1000_ICR_MDAC      /* MDIO access complete */
#define E1000_IMS_RXCFG     E1000_ICR_RXCFG     /* RX /c/ ordered set */
#define E1000_IMS_GPI_EN0   E1000_ICR_GPI_EN0   /* GP Int 0 */
#define E1000_IMS_GPI_EN1   E1000_ICR_GPI_EN1   /* GP Int 1 */
#define E1000_IMS_GPI_EN2   E1000_ICR_GPI_EN2   /* GP Int 2 */
#define E1000_IMS_GPI_EN3   E1000_ICR_GPI_EN3   /* GP Int 3 */
#define E1000_IMS_TXD_LOW   E1000_ICR_TXD_LOW
#define E1000_IMS_SRPD      E1000_ICR_SRPD
#define E1000_IMS_ACK       E1000_ICR_ACK       /* Receive Ack frame */
#define E1000_IMS_MNG       E1000_ICR_MNG       /* Manageability event */
#define E1000_IMS_DOCK      E1000_ICR_DOCK      /* Dock/Undock */
#define E1000_IMS_RXD_FIFO_PAR0 E1000_ICR_RXD_FIFO_PAR0 /* queue 0 Rx descriptor FIFO parity error */
#define E1000_IMS_TXD_FIFO_PAR0 E1000_ICR_TXD_FIFO_PAR0 /* queue 0 Tx descriptor FIFO parity error */
#define E1000_IMS_HOST_ARB_PAR  E1000_ICR_HOST_ARB_PAR  /* host arb read buffer parity error */
#define E1000_IMS_PB_PAR        E1000_ICR_PB_PAR        /* packet buffer parity error */
#define E1000_IMS_RXD_FIFO_PAR1 E1000_ICR_RXD_FIFO_PAR1 /* queue 1 Rx descriptor FIFO parity error */
#define E1000_IMS_TXD_FIFO_PAR1 E1000_ICR_TXD_FIFO_PAR1 /* queue 1 Tx descriptor FIFO parity error */
#define E1000_IMS_DSW       E1000_ICR_DSW
#define E1000_IMS_PHYINT    E1000_ICR_PHYINT
#define E1000_IMS_EPRST     E1000_ICR_EPRST

/* Interrupt Mask Clear */
#define E1000_IMC_TXDW      E1000_ICR_TXDW      /* Transmit desc written back */
#define E1000_IMC_TXQE      E1000_ICR_TXQE      /* Transmit Queue empty */
#define E1000_IMC_LSC       E1000_ICR_LSC       /* Link Status Change */
#define E1000_IMC_RXSEQ     E1000_ICR_RXSEQ     /* rx sequence error */
#define E1000_IMC_RXDMT0    E1000_ICR_RXDMT0    /* rx desc min. threshold */
#define E1000_IMC_RXO       E1000_ICR_RXO       /* rx overrun */
#define E1000_IMC_RXT0      E1000_ICR_RXT0      /* rx timer intr */
#define E1000_IMC_MDAC      E1000_ICR_MDAC      /* MDIO access complete */
#define E1000_IMC_RXCFG     E1000_ICR_RXCFG     /* RX /c/ ordered set */
#define E1000_IMC_GPI_EN0   E1000_ICR_GPI_EN0   /* GP Int 0 */
#define E1000_IMC_GPI_EN1   E1000_ICR_GPI_EN1   /* GP Int 1 */
#define E1000_IMC_GPI_EN2   E1000_ICR_GPI_EN2   /* GP Int 2 */
#define E1000_IMC_GPI_EN3   E1000_ICR_GPI_EN3   /* GP Int 3 */
#define E1000_IMC_TXD_LOW   E1000_ICR_TXD_LOW
#define E1000_IMC_SRPD      E1000_ICR_SRPD
#define E1000_IMC_ACK       E1000_ICR_ACK       /* Receive Ack frame */
#define E1000_IMC_MNG       E1000_ICR_MNG       /* Manageability event */
#define E1000_IMC_DOCK      E1000_ICR_DOCK      /* Dock/Undock */
#define E1000_IMC_RXD_FIFO_PAR0 E1000_ICR_RXD_FIFO_PAR0 /* queue 0 Rx descriptor FIFO parity error */
#define E1000_IMC_TXD_FIFO_PAR0 E1000_ICR_TXD_FIFO_PAR0 /* queue 0 Tx descriptor FIFO parity error */
#define E1000_IMC_HOST_ARB_PAR  E1000_ICR_HOST_ARB_PAR  /* host arb read buffer parity error */
#define E1000_IMC_PB_PAR        E1000_ICR_PB_PAR        /* packet buffer parity error */
#define E1000_IMC_RXD_FIFO_PAR1 E1000_ICR_RXD_FIFO_PAR1 /* queue 1 Rx descriptor FIFO parity error */
#define E1000_IMC_TXD_FIFO_PAR1 E1000_ICR_TXD_FIFO_PAR1 /* queue 1 Tx descriptor FIFO parity error */
#define E1000_IMC_DSW       E1000_ICR_DSW
#define E1000_IMC_PHYINT    E1000_ICR_PHYINT
#define E1000_IMC_EPRST     E1000_ICR_EPRST

/* Receive Control */
#define E1000_RCTL_RST            0x00000001    /* Software reset */
#define E1000_RCTL_EN             0x00000002    /* enable */
#define E1000_RCTL_SBP            0x00000004    /* store bad packet */
#define E1000_RCTL_UPE            0x00000008    /* unicast promiscuous enable */
#define E1000_RCTL_MPE            0x00000010    /* multicast promiscuous enab */
#define E1000_RCTL_LPE            0x00000020    /* long packet enable */
#define E1000_RCTL_LBM_NO         0x00000000    /* no loopback mode */
#define E1000_RCTL_LBM_MAC        0x00000040    /* MAC loopback mode */
#define E1000_RCTL_LBM_SLP        0x00000080    /* serial link loopback mode */
#define E1000_RCTL_LBM_TCVR       0x000000C0    /* tcvr loopback mode */
#define E1000_RCTL_DTYP_MASK      0x00000C00    /* Descriptor type mask */
#define E1000_RCTL_DTYP_PS        0x00000400    /* Packet Split descriptor */
#define E1000_RCTL_RDMTS_HALF     0x00000000    /* rx desc min threshold size */
#define E1000_RCTL_RDMTS_QUAT     0x00000100    /* rx desc min threshold size */
#define E1000_RCTL_RDMTS_EIGTH    0x00000200    /* rx desc min threshold size */
#define E1000_RCTL_MO_SHIFT       12            /* multicast offset shift */
#define E1000_RCTL_MO_0           0x00000000    /* multicast offset 11:0 */
#define E1000_RCTL_MO_1           0x00001000    /* multicast offset 12:1 */
#define E1000_RCTL_MO_2           0x00002000    /* multicast offset 13:2 */
#define E1000_RCTL_MO_3           0x00003000    /* multicast offset 15:4 */
#define E1000_RCTL_MDR            0x00004000    /* multicast desc ring 0 */
#define E1000_RCTL_BAM            0x00008000    /* broadcast enable */
/* these buffer sizes are valid if E1000_RCTL_BSEX is 0 */
#define E1000_RCTL_SZ_2048        0x00000000    /* rx buffer size 2048 */
#define E1000_RCTL_SZ_1024        0x00010000    /* rx buffer size 1024 */
#define E1000_RCTL_SZ_512         0x00020000    /* rx buffer size 512 */
#define E1000_RCTL_SZ_256         0x00030000    /* rx buffer size 256 */
/* these buffer sizes are valid if E1000_RCTL_BSEX is 1 */
#define E1000_RCTL_SZ_16384       0x00010000    /* rx buffer size 16384 */
#define E1000_RCTL_SZ_8192        0x00020000    /* rx buffer size 8192 */
#define E1000_RCTL_SZ_4096        0x00030000    /* rx buffer size 4096 */
#define E1000_RCTL_VFE            0x00040000    /* vlan filter enable */
#define E1000_RCTL_CFIEN          0x00080000    /* canonical form enable */
#define E1000_RCTL_CFI            0x00100000    /* canonical form indicator */
#define E1000_RCTL_DPF            0x00400000    /* discard pause frames */
#define E1000_RCTL_PMCF           0x00800000    /* pass MAC control frames */
#define E1000_RCTL_BSEX           0x02000000    /* Buffer size extension */
#define E1000_RCTL_SECRC          0x04000000    /* Strip Ethernet CRC */
#define E1000_RCTL_FLXBUF_MASK    0x78000000    /* Flexible buffer size */
#define E1000_RCTL_FLXBUF_SHIFT   27            /* Flexible buffer shift */


#define E1000_EEPROM_SWDPIN0   0x0001   /* SWDPIN 0 EEPROM Value */
#define E1000_EEPROM_LED_LOGIC 0x0020   /* Led Logic Word */
#define E1000_EEPROM_RW_REG_DATA   16   /* Offset to data in EEPROM read/write registers */
#define E1000_EEPROM_RW_REG_DONE   0x10 /* Offset to READ/WRITE done bit */
#define E1000_EEPROM_RW_REG_START  1    /* First bit for telling part to start operation */
#define E1000_EEPROM_RW_ADDR_SHIFT 8    /* Shift to the address bits */
#define E1000_EEPROM_POLL_WRITE    1    /* Flag for polling for write complete */
#define E1000_EEPROM_POLL_READ     0    /* Flag for polling for read complete */
/* Register Bit Masks */
/* Device Control */
#define E1000_CTRL_FD       0x00000001  /* Full duplex.0=half; 1=full */
#define E1000_CTRL_BEM      0x00000002  /* Endian Mode.0=little,1=big */
#define E1000_CTRL_PRIOR    0x00000004  /* Priority on PCI. 0=rx,1=fair */
#define E1000_CTRL_GIO_MASTER_DISABLE 0x00000004 /*Blocks new Master requests */
#define E1000_CTRL_LRST     0x00000008  /* Link reset. 0=normal,1=reset */
#define E1000_CTRL_TME      0x00000010  /* Test mode. 0=normal,1=test */
#define E1000_CTRL_SLE      0x00000020  /* Serial Link on 0=dis,1=en */
#define E1000_CTRL_ASDE     0x00000020  /* Auto-speed detect enable */
#define E1000_CTRL_SLU      0x00000040  /* Set link up (Force Link) */
#define E1000_CTRL_ILOS     0x00000080  /* Invert Loss-Of Signal */
#define E1000_CTRL_SPD_SEL  0x00000300  /* Speed Select Mask */
#define E1000_CTRL_SPD_10   0x00000000  /* Force 10Mb */
#define E1000_CTRL_SPD_100  0x00000100  /* Force 100Mb */
#define E1000_CTRL_SPD_1000 0x00000200  /* Force 1Gb */
#define E1000_CTRL_BEM32    0x00000400  /* Big Endian 32 mode */
#define E1000_CTRL_FRCSPD   0x00000800  /* Force Speed */
#define E1000_CTRL_FRCDPX   0x00001000  /* Force Duplex */
#define E1000_CTRL_D_UD_EN  0x00002000  /* Dock/Undock enable */
#define E1000_CTRL_D_UD_POLARITY 0x00004000 /* Defined polarity of Dock/Undock indication in SDP[0] */
#define E1000_CTRL_FORCE_PHY_RESET 0x00008000 /* Reset both PHY ports, through PHYRST_N pin */
#define E1000_CTRL_EXT_LINK_EN 0x00010000 /* enable link status from external LINK_0 and LINK_1 pins */
#define E1000_CTRL_SWDPIN0  0x00040000  /* SWDPIN 0 value */
#define E1000_CTRL_SWDPIN1  0x00080000  /* SWDPIN 1 value */
#define E1000_CTRL_SWDPIN2  0x00100000  /* SWDPIN 2 value */
#define E1000_CTRL_SWDPIN3  0x00200000  /* SWDPIN 3 value */
#define E1000_CTRL_SWDPIO0  0x00400000  /* SWDPIN 0 Input or output */
#define E1000_CTRL_SWDPIO1  0x00800000  /* SWDPIN 1 input or output */
#define E1000_CTRL_SWDPIO2  0x01000000  /* SWDPIN 2 input or output */
#define E1000_CTRL_SWDPIO3  0x02000000  /* SWDPIN 3 input or output */
#define E1000_CTRL_RST      0x04000000  /* Global reset */
#define E1000_CTRL_RFCE     0x08000000  /* Receive Flow Control enable */
#define E1000_CTRL_TFCE     0x10000000  /* Transmit flow control enable */
#define E1000_CTRL_RTE      0x20000000  /* Routing tag enable */
#define E1000_CTRL_VME      0x40000000  /* IEEE VLAN mode enable */
#define E1000_CTRL_PHY_RST  0x80000000  /* PHY Reset */
#define E1000_CTRL_SW2FW_INT 0x02000000  /* Initiate an interrupt to manageability engine */

/* Device Status */
#define E1000_STATUS_FD         0x00000001      /* Full duplex.0=half,1=full */
#define E1000_STATUS_LU         0x00000002      /* Link up.0=no,1=link */
#define E1000_STATUS_FUNC_MASK  0x0000000C      /* PCI Function Mask */
#define E1000_STATUS_FUNC_SHIFT 2
#define E1000_STATUS_FUNC_0     0x00000000      /* Function 0 */
#define E1000_STATUS_FUNC_1     0x00000004      /* Function 1 */
#define E1000_STATUS_TXOFF      0x00000010      /* transmission paused */
#define E1000_STATUS_TBIMODE    0x00000020      /* TBI mode */
#define E1000_STATUS_SPEED_MASK 0x000000C0
#define E1000_STATUS_SPEED_10   0x00000000      /* Speed 10Mb/s */
#define E1000_STATUS_SPEED_100  0x00000040      /* Speed 100Mb/s */
#define E1000_STATUS_SPEED_1000 0x00000080      /* Speed 1000Mb/s */
#define E1000_STATUS_LAN_INIT_DONE 0x00000200   /* Lan Init Completion
                                                   by EEPROM/Flash */
#define E1000_STATUS_ASDV       0x00000300      /* Auto speed detect value */
#define E1000_STATUS_DOCK_CI    0x00000800      /* Change in Dock/Undock state. Clear on write '0'. */
#define E1000_STATUS_GIO_MASTER_ENABLE 0x00080000 /* Status of Master requests. */
#define E1000_STATUS_MTXCKOK    0x00000400      /* MTX clock running OK */
#define E1000_STATUS_PCI66      0x00000800      /* In 66Mhz slot */
#define E1000_STATUS_BUS64      0x00001000      /* In 64 bit slot */
#define E1000_STATUS_PCIX_MODE  0x00002000      /* PCI-X mode */
#define E1000_STATUS_PCIX_SPEED 0x0000C000      /* PCI-X bus speed */
#define E1000_STATUS_BMC_SKU_0  0x00100000 /* BMC USB redirect disabled */
#define E1000_STATUS_BMC_SKU_1  0x00200000 /* BMC SRAM disabled */
#define E1000_STATUS_BMC_SKU_2  0x00400000 /* BMC SDRAM disabled */
#define E1000_STATUS_BMC_CRYPTO 0x00800000 /* BMC crypto disabled */
#define E1000_STATUS_BMC_LITE   0x01000000 /* BMC external code execution disabled */
#define E1000_STATUS_RGMII_ENABLE 0x02000000 /* RGMII disabled */
#define E1000_STATUS_FUSE_8       0x04000000
#define E1000_STATUS_FUSE_9       0x08000000
#define E1000_STATUS_SERDES0_DIS  0x10000000 /* SERDES disabled on port 0 */
#define E1000_STATUS_SERDES1_DIS  0x20000000 /* SERDES disabled on port 1 */

/* EEPROM/Flash Control */
#define E1000_EECD_SK        0x00000001 /* EEPROM Clock */
#define E1000_EECD_CS        0x00000002 /* EEPROM Chip Select */
#define E1000_EECD_DI        0x00000004 /* EEPROM Data In */
#define E1000_EECD_DO        0x00000008 /* EEPROM Data Out */
#define E1000_EECD_FWE_MASK  0x00000030
#define E1000_EECD_FWE_DIS   0x00000010 /* Disable FLASH writes */
#define E1000_EECD_FWE_EN    0x00000020 /* Enable FLASH writes */
#define E1000_EECD_FWE_SHIFT 4
#define E1000_EECD_REQ       0x00000040 /* EEPROM Access Request */
#define E1000_EECD_GNT       0x00000080 /* EEPROM Access Grant */
#define E1000_EECD_PRES      0x00000100 /* EEPROM Present */
#define E1000_EECD_SIZE      0x00000200 /* EEPROM Size (0=64 word 1=256 word) */
#define E1000_EECD_ADDR_BITS 0x00000400 /* EEPROM Addressing bits based on type
                                         * (0-small, 1-large) */
#define E1000_EECD_TYPE      0x00002000 /* EEPROM Type (1-SPI, 0-Microwire) */
#ifndef E1000_EEPROM_GRANT_ATTEMPTS
#define E1000_EEPROM_GRANT_ATTEMPTS 1000 /* EEPROM # attempts to gain grant */
#endif
#define E1000_EECD_AUTO_RD          0x00000200  /* EEPROM Auto Read done */
#define E1000_EECD_SIZE_EX_MASK     0x00007800  /* EEprom Size */
#define E1000_EECD_SIZE_EX_SHIFT    11
#define E1000_EECD_NVADDS    0x00018000 /* NVM Address Size */
#define E1000_EECD_SELSHAD   0x00020000 /* Select Shadow RAM */
#define E1000_EECD_INITSRAM  0x00040000 /* Initialize Shadow RAM */
#define E1000_EECD_FLUPD     0x00080000 /* Update FLASH */
#define E1000_EECD_AUPDEN    0x00100000 /* Enable Autonomous FLASH update */
#define E1000_EECD_SHADV     0x00200000 /* Shadow RAM Data Valid */
#define E1000_EECD_SEC1VAL   0x00400000 /* Sector One Valid */
#define E1000_EECD_SECVAL_SHIFT      22
#define E1000_STM_OPCODE     0xDB00
#define E1000_HICR_FW_RESET  0xC0

#define E1000_SHADOW_RAM_WORDS     2048
#define E1000_ICH_NVM_SIG_WORD     0x13
#define E1000_ICH_NVM_SIG_MASK     0xC0

/* MDI Control */
#define E1000_MDIC_DATA_MASK 0x0000FFFF
#define E1000_MDIC_REG_MASK  0x001F0000
#define E1000_MDIC_REG_SHIFT 16
#define E1000_MDIC_PHY_MASK  0x03E00000
#define E1000_MDIC_PHY_SHIFT 21
#define E1000_MDIC_OP_WRITE  0x04000000
#define E1000_MDIC_OP_READ   0x08000000
#define E1000_MDIC_READY     0x10000000
#define E1000_MDIC_INT_EN    0x20000000
#define E1000_MDIC_ERROR     0x40000000

/* EEPROM Commands - Microwire */
#define EEPROM_READ_OPCODE_MICROWIRE  0x6  /* EEPROM read opcode */
#define EEPROM_WRITE_OPCODE_MICROWIRE 0x5  /* EEPROM write opcode */
#define EEPROM_ERASE_OPCODE_MICROWIRE 0x7  /* EEPROM erase opcode */
#define EEPROM_EWEN_OPCODE_MICROWIRE  0x13 /* EEPROM erase/write enable */
#define EEPROM_EWDS_OPCODE_MICROWIRE  0x10 /* EEPROM erast/write disable */

/* EEPROM Word Offsets */
#define EEPROM_COMPAT                 0x0003
#define EEPROM_ID_LED_SETTINGS        0x0004
#define EEPROM_VERSION                0x0005
#define EEPROM_SERDES_AMPLITUDE       0x0006 /* For SERDES output amplitude adjustment. */
#define EEPROM_PHY_CLASS_WORD         0x0007
#define EEPROM_INIT_CONTROL1_REG      0x000A
#define EEPROM_INIT_CONTROL2_REG      0x000F
#define EEPROM_SWDEF_PINS_CTRL_PORT_1 0x0010
#define EEPROM_INIT_CONTROL3_PORT_B   0x0014
#define EEPROM_INIT_3GIO_3            0x001A
#define EEPROM_SWDEF_PINS_CTRL_PORT_0 0x0020
#define EEPROM_INIT_CONTROL3_PORT_A   0x0024
#define EEPROM_CFG                    0x0012
#define EEPROM_FLASH_VERSION          0x0032
#define EEPROM_CHECKSUM_REG           0x003F

#define E1000_EEPROM_CFG_DONE         0x00040000   /* MNG config cycle done */
#define E1000_EEPROM_CFG_DONE_PORT_1  0x00080000   /* ...for second port */

/* Transmit Descriptor */
struct e1000_tx_desc {
    uint64_t buffer_addr;       /* Address of the descriptor's data buffer */
    union {
        uint32_t data;
        struct {
            uint16_t length;    /* Data buffer length */
            uint8_t cso;        /* Checksum offset */
            uint8_t cmd;        /* Descriptor control */
        } flags;
    } lower;
    union {
        uint32_t data;
        struct {
            uint8_t status;     /* Descriptor status */
            uint8_t css;        /* Checksum start */
            uint16_t special;
        } fields;
    } upper;
};

/* Transmit Descriptor bit definitions */
#define E1000_TXD_DTYP_D     0x00100000 /* Data Descriptor */
#define E1000_TXD_DTYP_C     0x00000000 /* Context Descriptor */
#define E1000_TXD_POPTS_IXSM 0x01       /* Insert IP checksum */
#define E1000_TXD_POPTS_TXSM 0x02       /* Insert TCP/UDP checksum */
#define E1000_TXD_CMD_EOP    0x01000000 /* End of Packet */
#define E1000_TXD_CMD_IFCS   0x02000000 /* Insert FCS (Ethernet CRC) */
#define E1000_TXD_CMD_IC     0x04000000 /* Insert Checksum */
#define E1000_TXD_CMD_RS     0x08000000 /* Report Status */
#define E1000_TXD_CMD_RPS    0x10000000 /* Report Packet Sent */
#define E1000_TXD_CMD_DEXT   0x20000000 /* Descriptor extension (0 = legacy) */
#define E1000_TXD_CMD_VLE    0x40000000 /* Add VLAN tag */
#define E1000_TXD_CMD_IDE    0x80000000 /* Enable Tidv register */
#define E1000_TXD_STAT_DD    0x00000001 /* Descriptor Done */
#define E1000_TXD_STAT_EC    0x00000002 /* Excess Collisions */
#define E1000_TXD_STAT_LC    0x00000004 /* Late Collisions */
#define E1000_TXD_STAT_TU    0x00000008 /* Transmit underrun */
#define E1000_TXD_CMD_TCP    0x01000000 /* TCP packet */
#define E1000_TXD_CMD_IP     0x02000000 /* IP packet */
#define E1000_TXD_CMD_TSE    0x04000000 /* TCP Seg enable */
#define E1000_TXD_STAT_TC    0x00000004 /* Tx Underrun */

/* Transmit Control */
#define E1000_TCTL_RST    0x00000001    /* software reset */
#define E1000_TCTL_EN     0x00000002    /* enable tx */
#define E1000_TCTL_BCE    0x00000004    /* busy check enable */
#define E1000_TCTL_PSP    0x00000008    /* pad short packets */
#define E1000_TCTL_CT     0x00000ff0    /* collision threshold */
#define E1000_TCTL_COLD   0x003ff000    /* collision distance */
#define E1000_TCTL_SWXOFF 0x00400000    /* SW Xoff transmission */
#define E1000_TCTL_PBE    0x00800000    /* Packet Burst Enable */
#define E1000_TCTL_RTLC   0x01000000    /* Re-transmit on late collision */
#define E1000_TCTL_NRTU   0x02000000    /* No Re-transmit on underrun */
#define E1000_TCTL_MULR   0x10000000    /* Multiple request support */

/* Receive Descriptor */
struct e1000_rx_desc {
    uint64_t buffer_addr; /* Address of the descriptor's data buffer */
    uint16_t length;     /* Length of data DMAed into data buffer */
    uint16_t csum;       /* Packet checksum */
    uint8_t status;      /* Descriptor status */
    uint8_t errors;      /* Descriptor Errors */
    uint16_t special;
};

/* Receive Descriptor bit definitions */
#define E1000_RXD_STAT_DD       0x01    /* Descriptor Done */
#define E1000_RXD_STAT_EOP      0x02    /* End of Packet */
#define E1000_RXD_STAT_IXSM     0x04    /* Ignore checksum */
#define E1000_RXD_STAT_VP       0x08    /* IEEE VLAN Packet */
#define E1000_RXD_STAT_UDPCS    0x10    /* UDP xsum caculated */
#define E1000_RXD_STAT_TCPCS    0x20    /* TCP xsum calculated */
#define E1000_RXD_STAT_IPCS     0x40    /* IP xsum calculated */
#define E1000_RXD_STAT_PIF      0x80    /* passed in-exact filter */
#define E1000_RXD_STAT_IPIDV    0x200   /* IP identification valid */
#define E1000_RXD_STAT_UDPV     0x400   /* Valid UDP checksum */
#define E1000_RXD_STAT_ACK      0x8000  /* ACK Packet indication */
#define E1000_RXD_ERR_CE        0x01    /* CRC Error */
#define E1000_RXD_ERR_SE        0x02    /* Symbol Error */
#define E1000_RXD_ERR_SEQ       0x04    /* Sequence Error */
#define E1000_RXD_ERR_CXE       0x10    /* Carrier Extension Error */
#define E1000_RXD_ERR_TCPE      0x20    /* TCP/UDP Checksum Error */
#define E1000_RXD_ERR_IPE       0x40    /* IP Checksum Error */
#define E1000_RXD_ERR_RXE       0x80    /* Rx Data Error */
#define E1000_RXD_SPC_VLAN_MASK 0x0FFF  /* VLAN ID is in lower 12 bits */
#define E1000_RXD_SPC_PRI_MASK  0xE000  /* Priority is in upper 3 bits */
#define E1000_RXD_SPC_PRI_SHIFT 13
#define E1000_RXD_SPC_CFI_MASK  0x1000  /* CFI is bit 12 */
#define E1000_RXD_SPC_CFI_SHIFT 12

#define E1000_RXDEXT_STATERR_CE    0x01000000
#define E1000_RXDEXT_STATERR_SE    0x02000000
#define E1000_RXDEXT_STATERR_SEQ   0x04000000
#define E1000_RXDEXT_STATERR_CXE   0x10000000
#define E1000_RXDEXT_STATERR_TCPE  0x20000000
#define E1000_RXDEXT_STATERR_IPE   0x40000000
#define E1000_RXDEXT_STATERR_RXE   0x80000000

#define E1000_RXDPS_HDRSTAT_HDRSP        0x00008000
#define E1000_RXDPS_HDRSTAT_HDRLEN_MASK  0x000003FF

/* Receive Address */
#define E1000_RAH_AV  0x80000000        /* Receive descriptor valid */

/* Offload Context Descriptor */
struct e1000_context_desc {
    union {
        uint32_t ip_config;
        struct {
            uint8_t ipcss;      /* IP checksum start */
            uint8_t ipcso;      /* IP checksum offset */
            uint16_t ipcse;     /* IP checksum end */
        } ip_fields;
    } lower_setup;
    union {
        uint32_t tcp_config;
        struct {
            uint8_t tucss;      /* TCP checksum start */
            uint8_t tucso;      /* TCP checksum offset */
            uint16_t tucse;     /* TCP checksum end */
        } tcp_fields;
    } upper_setup;
    uint32_t cmd_and_length;    /* */
    union {
        uint32_t data;
        struct {
            uint8_t status;     /* Descriptor status */
            uint8_t hdr_len;    /* Header length */
            uint16_t mss;       /* Maximum segment size */
        } fields;
    } tcp_seg_setup;
};

/* Offload data descriptor */
struct e1000_data_desc {
    uint64_t buffer_addr;       /* Address of the descriptor's buffer address */
    union {
        uint32_t data;
        struct {
            uint16_t length;    /* Data buffer length */
            uint8_t typ_len_ext;        /* */
            uint8_t cmd;        /* */
        } flags;
    } lower;
    union {
        uint32_t data;
        struct {
            uint8_t status;     /* Descriptor status */
            uint8_t popts;      /* Packet Options */
            uint16_t special;   /* */
        } fields;
    } upper;
};

/* Management Control */
#define E1000_MANC_SMBUS_EN      0x00000001 /* SMBus Enabled - RO */
#define E1000_MANC_ASF_EN        0x00000002 /* ASF Enabled - RO */
#define E1000_MANC_R_ON_FORCE    0x00000004 /* Reset on Force TCO - RO */
#define E1000_MANC_RMCP_EN       0x00000100 /* Enable RCMP 026Fh Filtering */
#define E1000_MANC_0298_EN       0x00000200 /* Enable RCMP 0298h Filtering */
#define E1000_MANC_IPV4_EN       0x00000400 /* Enable IPv4 */
#define E1000_MANC_IPV6_EN       0x00000800 /* Enable IPv6 */
#define E1000_MANC_SNAP_EN       0x00001000 /* Accept LLC/SNAP */
#define E1000_MANC_ARP_EN        0x00002000 /* Enable ARP Request Filtering */
#define E1000_MANC_NEIGHBOR_EN   0x00004000 /* Enable Neighbor Discovery
                                             * Filtering */
#define E1000_MANC_ARP_RES_EN    0x00008000 /* Enable ARP response Filtering */
#define E1000_MANC_TCO_RESET     0x00010000 /* TCO Reset Occurred */
#define E1000_MANC_RCV_TCO_EN    0x00020000 /* Receive TCO Packets Enabled */
#define E1000_MANC_REPORT_STATUS 0x00040000 /* Status Reporting Enabled */
#define E1000_MANC_RCV_ALL       0x00080000 /* Receive All Enabled */
#define E1000_MANC_BLK_PHY_RST_ON_IDE   0x00040000 /* Block phy resets */
#define E1000_MANC_EN_MAC_ADDR_FILTER   0x00100000 /* Enable MAC address
                                                    * filtering */
#define E1000_MANC_EN_MNG2HOST   0x00200000 /* Enable MNG packets to host
                                             * memory */
#define E1000_MANC_EN_IP_ADDR_FILTER    0x00400000 /* Enable IP address
                                                    * filtering */
#define E1000_MANC_EN_XSUM_FILTER   0x00800000 /* Enable checksum filtering */
#define E1000_MANC_BR_EN         0x01000000 /* Enable broadcast filtering */
#define E1000_MANC_SMB_REQ       0x01000000 /* SMBus Request */
#define E1000_MANC_SMB_GNT       0x02000000 /* SMBus Grant */
#define E1000_MANC_SMB_CLK_IN    0x04000000 /* SMBus Clock In */
#define E1000_MANC_SMB_DATA_IN   0x08000000 /* SMBus Data In */
#define E1000_MANC_SMB_DATA_OUT  0x10000000 /* SMBus Data Out */
#define E1000_MANC_SMB_CLK_OUT   0x20000000 /* SMBus Clock Out */

#define E1000_MANC_SMB_DATA_OUT_SHIFT  28 /* SMBus Data Out Shift */
#define E1000_MANC_SMB_CLK_OUT_SHIFT   29 /* SMBus Clock Out Shift */

/* For checksumming, the sum of all words in the EEPROM should equal 0xBABA. */
#define EEPROM_SUM 0xBABA


#define E1000_DEBUG

#ifdef E1000_DEBUG
enum {
    DEBUG_GENERAL,	DEBUG_IO,	DEBUG_MMIO,	DEBUG_INTERRUPT,
    DEBUG_RX,		DEBUG_TX,	DEBUG_MDIC,	DEBUG_EEPROM,
    DEBUG_UNKNOWN,	DEBUG_TXSUM,	DEBUG_TXERR,	DEBUG_RXERR,
    DEBUG_RXFILTER,	DEBUG_NOTYET,
};
#define DBGBIT(x)	(1<<DEBUG_##x)
static int debugflags = DBGBIT(TXERR) | DBGBIT(GENERAL);

#define	DBGOUT(what, fmt, ...) do { \
    if (debugflags & DBGBIT(what)) \
        fprintf(stderr, "e1000: " fmt, ## __VA_ARGS__); \
    } while (0)
#else
#define	DBGOUT(what, fmt, ...) do {} while (0)
#endif

#define IOPORT_SIZE       0x40
#define PNPMMIO_SIZE      0x20000
#define MIN_BUF_SIZE      60 /* Min. octets in an ethernet frame sans FCS */

/*
 * HW models:
 *  E1000_DEV_ID_82540EM works with Windows and Linux
 *  E1000_DEV_ID_82573L OK with windoze and Linux 2.6.22,
 *	appears to perform better than 82540EM, but breaks with Linux 2.6.18
 *  E1000_DEV_ID_82544GC_COPPER appears to work; not well tested
 *  Others never tested
 */
enum { E1000_DEVID = E1000_DEV_ID_82540EM };

/*
 * May need to specify additional MAC-to-PHY entries --
 * Intel's Windows driver refuses to initialize unless they match
 */
enum {
    PHY_ID2_INIT = E1000_DEVID == E1000_DEV_ID_82573L ?		0xcc2 :
                   E1000_DEVID == E1000_DEV_ID_82544GC_COPPER ?	0xc30 :
                   /* default to E1000_DEV_ID_82540EM */	0xc20
};

typedef struct E1000State_st {
    PCIDevice dev;
    NICState *nic;
    NICConf conf;
    MemoryRegion mmio;
    MemoryRegion io;

    uint32_t mac_reg[0x8000];
    uint16_t phy_reg[0x20];
    uint16_t eeprom_data[64];

    uint32_t rxbuf_size;
    uint32_t rxbuf_min_shift;
    int check_rxov;
    struct e1000_tx {
        unsigned char header[256];
        unsigned char vlan_header[4];
        /* Fields vlan and data must not be reordered or separated. */
        unsigned char vlan[4];
        unsigned char data[0x10000];
        uint16_t size;
        unsigned char sum_needed;
        unsigned char vlan_needed;
        uint8_t ipcss;
        uint8_t ipcso;
        uint16_t ipcse;
        uint8_t tucss;
        uint8_t tucso;
        uint16_t tucse;
        uint8_t hdr_len;
        uint16_t mss;
        uint32_t paylen;
        uint16_t tso_frames;
        char tse;
        int8_t ip;
        int8_t tcp;
        char cptse;     // current packet tse bit
    } tx;

    struct {
        uint32_t val_in;	// shifted in from guest driver
        uint16_t bitnum_in;
        uint16_t bitnum_out;
        uint16_t reading;
        uint32_t old_eecd;
    } eecd_state;
} E1000State;

#define	defreg(x)	x = (E1000_##x>>2)
enum {
    defreg(CTRL),	defreg(EECD),	defreg(EERD),	defreg(GPRC),
    defreg(GPTC),	defreg(ICR),	defreg(ICS),	defreg(IMC),
    defreg(IMS),	defreg(LEDCTL),	defreg(MANC),	defreg(MDIC),
    defreg(MPC),	defreg(PBA),	defreg(RCTL),	defreg(RDBAH),
    defreg(RDBAL),	defreg(RDH),	defreg(RDLEN),	defreg(RDT),
    defreg(STATUS),	defreg(SWSM),	defreg(TCTL),	defreg(TDBAH),
    defreg(TDBAL),	defreg(TDH),	defreg(TDLEN),	defreg(TDT),
    defreg(TORH),	defreg(TORL),	defreg(TOTH),	defreg(TOTL),
    defreg(TPR),	defreg(TPT),	defreg(TXDCTL),	defreg(WUFC),
    defreg(RA),		defreg(MTA),	defreg(CRCERRS),defreg(VFTA),
    defreg(VET),
};

enum { PHY_R = 1, PHY_W = 2, PHY_RW = PHY_R | PHY_W };
static const char phy_regcap[0x20] = {
    [PHY_STATUS] = PHY_R,	[M88E1000_EXT_PHY_SPEC_CTRL] = PHY_RW,
    [PHY_ID1] = PHY_R,		[M88E1000_PHY_SPEC_CTRL] = PHY_RW,
    [PHY_CTRL] = PHY_RW,	[PHY_1000T_CTRL] = PHY_RW,
    [PHY_LP_ABILITY] = PHY_R,	[PHY_1000T_STATUS] = PHY_R,
    [PHY_AUTONEG_ADV] = PHY_RW,	[M88E1000_RX_ERR_CNTR] = PHY_R,
    [PHY_ID2] = PHY_R,		[M88E1000_PHY_SPEC_STATUS] = PHY_R
};

static void
set_interrupt_cause(E1000State *s, int index, uint32_t val)
{
    if (val)
        val |= E1000_ICR_INT_ASSERTED;
    s->mac_reg[ICR] = val;
    s->mac_reg[ICS] = val;
    qemu_set_irq(s->dev.irq[0], (s->mac_reg[IMS] & s->mac_reg[ICR]) != 0);
}

static void
set_ics(E1000State *s, int index, uint32_t val)
{
    DBGOUT(INTERRUPT, "set_ics %x, ICR %x, IMR %x\n", val, s->mac_reg[ICR],
        s->mac_reg[IMS]);
    set_interrupt_cause(s, 0, val | s->mac_reg[ICR]);
}

static int
rxbufsize(uint32_t v)
{
    v &= E1000_RCTL_BSEX | E1000_RCTL_SZ_16384 | E1000_RCTL_SZ_8192 |
         E1000_RCTL_SZ_4096 | E1000_RCTL_SZ_2048 | E1000_RCTL_SZ_1024 |
         E1000_RCTL_SZ_512 | E1000_RCTL_SZ_256;
    switch (v) {
    case E1000_RCTL_BSEX | E1000_RCTL_SZ_16384:
        return 16384;
    case E1000_RCTL_BSEX | E1000_RCTL_SZ_8192:
        return 8192;
    case E1000_RCTL_BSEX | E1000_RCTL_SZ_4096:
        return 4096;
    case E1000_RCTL_SZ_1024:
        return 1024;
    case E1000_RCTL_SZ_512:
        return 512;
    case E1000_RCTL_SZ_256:
        return 256;
    }
    return 2048;
}

static void
set_ctrl(E1000State *s, int index, uint32_t val)
{
    /* RST is self clearing */
    s->mac_reg[CTRL] = val & ~E1000_CTRL_RST;
}

static void
set_rx_control(E1000State *s, int index, uint32_t val)
{
    s->mac_reg[RCTL] = val;
    s->rxbuf_size = rxbufsize(val);
    s->rxbuf_min_shift = ((val / E1000_RCTL_RDMTS_QUAT) & 3) + 1;
    DBGOUT(RX, "RCTL: %d, mac_reg[RCTL] = 0x%x\n", s->mac_reg[RDT],
           s->mac_reg[RCTL]);
}

static void
set_mdic(E1000State *s, int index, uint32_t val)
{
    uint32_t data = val & E1000_MDIC_DATA_MASK;
    uint32_t addr = ((val & E1000_MDIC_REG_MASK) >> E1000_MDIC_REG_SHIFT);

    if ((val & E1000_MDIC_PHY_MASK) >> E1000_MDIC_PHY_SHIFT != 1) // phy #
        val = s->mac_reg[MDIC] | E1000_MDIC_ERROR;
    else if (val & E1000_MDIC_OP_READ) {
        DBGOUT(MDIC, "MDIC read reg 0x%x\n", addr);
        if (!(phy_regcap[addr] & PHY_R)) {
            DBGOUT(MDIC, "MDIC read reg %x unhandled\n", addr);
            val |= E1000_MDIC_ERROR;
        } else
            val = (val ^ data) | s->phy_reg[addr];
    } else if (val & E1000_MDIC_OP_WRITE) {
        DBGOUT(MDIC, "MDIC write reg 0x%x, value 0x%x\n", addr, data);
        if (!(phy_regcap[addr] & PHY_W)) {
            DBGOUT(MDIC, "MDIC write reg %x unhandled\n", addr);
            val |= E1000_MDIC_ERROR;
        } else
            s->phy_reg[addr] = data;
    }
    s->mac_reg[MDIC] = val | E1000_MDIC_READY;
    set_ics(s, 0, E1000_ICR_MDAC);
}

static uint32_t
get_eecd(E1000State *s, int index)
{
    uint32_t ret = E1000_EECD_PRES|E1000_EECD_GNT | s->eecd_state.old_eecd;

    DBGOUT(EEPROM, "reading eeprom bit %d (reading %d)\n",
           s->eecd_state.bitnum_out, s->eecd_state.reading);
    if (!s->eecd_state.reading ||
        ((s->eeprom_data[(s->eecd_state.bitnum_out >> 4) & 0x3f] >>
          ((s->eecd_state.bitnum_out & 0xf) ^ 0xf))) & 1)
        ret |= E1000_EECD_DO;
    return ret;
}

static void
set_eecd(E1000State *s, int index, uint32_t val)
{
    uint32_t oldval = s->eecd_state.old_eecd;

    s->eecd_state.old_eecd = val & (E1000_EECD_SK | E1000_EECD_CS |
            E1000_EECD_DI|E1000_EECD_FWE_MASK|E1000_EECD_REQ);
    if (!(E1000_EECD_CS & val))			// CS inactive; nothing to do
	return;
    if (E1000_EECD_CS & (val ^ oldval)) {	// CS rise edge; reset state
	s->eecd_state.val_in = 0;
	s->eecd_state.bitnum_in = 0;
	s->eecd_state.bitnum_out = 0;
	s->eecd_state.reading = 0;
    }
    if (!(E1000_EECD_SK & (val ^ oldval)))	// no clock edge
        return;
    if (!(E1000_EECD_SK & val)) {		// falling edge
        s->eecd_state.bitnum_out++;
        return;
    }
    s->eecd_state.val_in <<= 1;
    if (val & E1000_EECD_DI)
        s->eecd_state.val_in |= 1;
    if (++s->eecd_state.bitnum_in == 9 && !s->eecd_state.reading) {
        s->eecd_state.bitnum_out = ((s->eecd_state.val_in & 0x3f)<<4)-1;
        s->eecd_state.reading = (((s->eecd_state.val_in >> 6) & 7) ==
            EEPROM_READ_OPCODE_MICROWIRE);
    }
    DBGOUT(EEPROM, "eeprom bitnum in %d out %d, reading %d\n",
           s->eecd_state.bitnum_in, s->eecd_state.bitnum_out,
           s->eecd_state.reading);
}

static uint32_t
flash_eerd_read(E1000State *s, int x)
{
    unsigned int index, r = s->mac_reg[EERD] & ~E1000_EEPROM_RW_REG_START;

    if ((s->mac_reg[EERD] & E1000_EEPROM_RW_REG_START) == 0)
        return (s->mac_reg[EERD]);

    if ((index = r >> E1000_EEPROM_RW_ADDR_SHIFT) > EEPROM_CHECKSUM_REG)
        return (E1000_EEPROM_RW_REG_DONE | r);

    return ((s->eeprom_data[index] << E1000_EEPROM_RW_REG_DATA) |
           E1000_EEPROM_RW_REG_DONE | r);
}

static void
putsum(uint8_t *data, uint32_t n, uint32_t sloc, uint32_t css, uint32_t cse)
{
    uint32_t sum;

    if (cse && cse < n)
        n = cse + 1;
    if (sloc < n-1) {
        sum = net_checksum_add(n-css, data+css);
        cpu_to_be16wu((uint16_t *)(data + sloc),
                      net_checksum_finish(sum));
    }
}

static inline int
vlan_enabled(E1000State *s)
{
    return ((s->mac_reg[CTRL] & E1000_CTRL_VME) != 0);
}

static inline int
vlan_rx_filter_enabled(E1000State *s)
{
    return ((s->mac_reg[RCTL] & E1000_RCTL_VFE) != 0);
}

static inline int
is_vlan_packet(E1000State *s, const uint8_t *buf)
{
    return (be16_to_cpup((uint16_t *)(buf + 12)) ==
                le16_to_cpup((uint16_t *)(s->mac_reg + VET)));
}

static inline int
is_vlan_txd(uint32_t txd_lower)
{
    return ((txd_lower & E1000_TXD_CMD_VLE) != 0);
}

/* FCS aka Ethernet CRC-32. We don't get it from backends and can't
 * fill it in, just pad descriptor length by 4 bytes unless guest
 * told us to strip it off the packet. */
static inline int
fcs_len(E1000State *s)
{
    return (s->mac_reg[RCTL] & E1000_RCTL_SECRC) ? 0 : 4;
}

static void
xmit_seg(E1000State *s)
{
    uint16_t len, *sp;
    unsigned int frames = s->tx.tso_frames, css, sofar, n;
    struct e1000_tx *tp = &s->tx;

    if (tp->tse && tp->cptse) {
        css = tp->ipcss;
        DBGOUT(TXSUM, "frames %d size %d ipcss %d\n",
               frames, tp->size, css);
        if (tp->ip) {		// IPv4
            cpu_to_be16wu((uint16_t *)(tp->data+css+2),
                          tp->size - css);
            cpu_to_be16wu((uint16_t *)(tp->data+css+4),
                          be16_to_cpup((uint16_t *)(tp->data+css+4))+frames);
        } else			// IPv6
            cpu_to_be16wu((uint16_t *)(tp->data+css+4),
                          tp->size - css);
        css = tp->tucss;
        len = tp->size - css;
        DBGOUT(TXSUM, "tcp %d tucss %d len %d\n", tp->tcp, css, len);
        if (tp->tcp) {
            sofar = frames * tp->mss;
            cpu_to_be32wu((uint32_t *)(tp->data+css+4),	// seq
                be32_to_cpupu((uint32_t *)(tp->data+css+4))+sofar);
            if (tp->paylen - sofar > tp->mss)
                tp->data[css + 13] &= ~9;		// PSH, FIN
        } else	// UDP
            cpu_to_be16wu((uint16_t *)(tp->data+css+4), len);
        if (tp->sum_needed & E1000_TXD_POPTS_TXSM) {
            unsigned int phsum;
            // add pseudo-header length before checksum calculation
            sp = (uint16_t *)(tp->data + tp->tucso);
            phsum = be16_to_cpup(sp) + len;
            phsum = (phsum >> 16) + (phsum & 0xffff);
            cpu_to_be16wu(sp, phsum);
        }
        tp->tso_frames++;
    }

    if (tp->sum_needed & E1000_TXD_POPTS_TXSM)
        putsum(tp->data, tp->size, tp->tucso, tp->tucss, tp->tucse);
    if (tp->sum_needed & E1000_TXD_POPTS_IXSM)
        putsum(tp->data, tp->size, tp->ipcso, tp->ipcss, tp->ipcse);
    if (tp->vlan_needed) {
        memmove(tp->vlan, tp->data, 4);
        memmove(tp->data, tp->data + 4, 8);
        memcpy(tp->data + 8, tp->vlan_header, 4);
        qemu_send_packet(&s->nic->nc, tp->vlan, tp->size + 4);
    } else
        qemu_send_packet(&s->nic->nc, tp->data, tp->size);
    s->mac_reg[TPT]++;
    s->mac_reg[GPTC]++;
    n = s->mac_reg[TOTL];
    if ((s->mac_reg[TOTL] += s->tx.size) < n)
        s->mac_reg[TOTH]++;
}

static void
process_tx_desc(E1000State *s, struct e1000_tx_desc *dp)
{
    uint32_t txd_lower = le32_to_cpu(dp->lower.data);
    uint32_t dtype = txd_lower & (E1000_TXD_CMD_DEXT | E1000_TXD_DTYP_D);
    unsigned int split_size = txd_lower & 0xffff, bytes, sz, op;
    unsigned int msh = 0xfffff, hdr = 0;
    uint64_t addr;
    struct e1000_context_desc *xp = (struct e1000_context_desc *)dp;
    struct e1000_tx *tp = &s->tx;

    if (dtype == E1000_TXD_CMD_DEXT) {	// context descriptor
        op = le32_to_cpu(xp->cmd_and_length);
        tp->ipcss = xp->lower_setup.ip_fields.ipcss;
        tp->ipcso = xp->lower_setup.ip_fields.ipcso;
        tp->ipcse = le16_to_cpu(xp->lower_setup.ip_fields.ipcse);
        tp->tucss = xp->upper_setup.tcp_fields.tucss;
        tp->tucso = xp->upper_setup.tcp_fields.tucso;
        tp->tucse = le16_to_cpu(xp->upper_setup.tcp_fields.tucse);
        tp->paylen = op & 0xfffff;
        tp->hdr_len = xp->tcp_seg_setup.fields.hdr_len;
        tp->mss = le16_to_cpu(xp->tcp_seg_setup.fields.mss);
        tp->ip = (op & E1000_TXD_CMD_IP) ? 1 : 0;
        tp->tcp = (op & E1000_TXD_CMD_TCP) ? 1 : 0;
        tp->tse = (op & E1000_TXD_CMD_TSE) ? 1 : 0;
        tp->tso_frames = 0;
        if (tp->tucso == 0) {	// this is probably wrong
            DBGOUT(TXSUM, "TCP/UDP: cso 0!\n");
            tp->tucso = tp->tucss + (tp->tcp ? 16 : 6);
        }
        return;
    } else if (dtype == (E1000_TXD_CMD_DEXT | E1000_TXD_DTYP_D)) {
        // data descriptor
        if (tp->size == 0) {
            tp->sum_needed = le32_to_cpu(dp->upper.data) >> 8;
        }
        tp->cptse = ( txd_lower & E1000_TXD_CMD_TSE ) ? 1 : 0;
    } else {
        // legacy descriptor
        tp->cptse = 0;
    }

    if (vlan_enabled(s) && is_vlan_txd(txd_lower) &&
        (tp->cptse || txd_lower & E1000_TXD_CMD_EOP)) {
        tp->vlan_needed = 1;
        cpu_to_be16wu((uint16_t *)(tp->vlan_header),
                      le16_to_cpup((uint16_t *)(s->mac_reg + VET)));
        cpu_to_be16wu((uint16_t *)(tp->vlan_header + 2),
                      le16_to_cpu(dp->upper.fields.special));
    }
        
    addr = le64_to_cpu(dp->buffer_addr);
    if (tp->tse && tp->cptse) {
        hdr = tp->hdr_len;
        msh = hdr + tp->mss;
        do {
            bytes = split_size;
            if (tp->size + bytes > msh)
                bytes = msh - tp->size;
            pci_dma_read(&s->dev, addr, tp->data + tp->size, bytes);
            if ((sz = tp->size + bytes) >= hdr && tp->size < hdr)
                memmove(tp->header, tp->data, hdr);
            tp->size = sz;
            addr += bytes;
            if (sz == msh) {
                xmit_seg(s);
                memmove(tp->data, tp->header, hdr);
                tp->size = hdr;
            }
        } while (split_size -= bytes);
    } else if (!tp->tse && tp->cptse) {
        // context descriptor TSE is not set, while data descriptor TSE is set
        DBGOUT(TXERR, "TCP segmentaion Error\n");
    } else {
        pci_dma_read(&s->dev, addr, tp->data + tp->size, split_size);
        tp->size += split_size;
    }

    if (!(txd_lower & E1000_TXD_CMD_EOP))
        return;
    if (!(tp->tse && tp->cptse && tp->size < hdr))
        xmit_seg(s);
    tp->tso_frames = 0;
    tp->sum_needed = 0;
    tp->vlan_needed = 0;
    tp->size = 0;
    tp->cptse = 0;
}

static uint32_t
txdesc_writeback(E1000State *s, dma_addr_t base, struct e1000_tx_desc *dp)
{
    uint32_t txd_upper, txd_lower = le32_to_cpu(dp->lower.data);

    if (!(txd_lower & (E1000_TXD_CMD_RS|E1000_TXD_CMD_RPS)))
        return 0;
    txd_upper = (le32_to_cpu(dp->upper.data) | E1000_TXD_STAT_DD) &
                ~(E1000_TXD_STAT_EC | E1000_TXD_STAT_LC | E1000_TXD_STAT_TU);
    dp->upper.data = cpu_to_le32(txd_upper);
    pci_dma_write(&s->dev, base + ((char *)&dp->upper - (char *)dp),
                  (void *)&dp->upper, sizeof(dp->upper));
    return E1000_ICR_TXDW;
}

static uint64_t tx_desc_base(E1000State *s)
{
    uint64_t bah = s->mac_reg[TDBAH];
    uint64_t bal = s->mac_reg[TDBAL] & ~0xf;

    return (bah << 32) + bal;
}

static void
start_xmit(E1000State *s)
{
    dma_addr_t base;
    struct e1000_tx_desc desc;
    uint32_t tdh_start = s->mac_reg[TDH], cause = E1000_ICS_TXQE;

    if (!(s->mac_reg[TCTL] & E1000_TCTL_EN)) {
        DBGOUT(TX, "tx disabled\n");
        return;
    }

    while (s->mac_reg[TDH] != s->mac_reg[TDT]) {
        base = tx_desc_base(s) +
               sizeof(struct e1000_tx_desc) * s->mac_reg[TDH];
        pci_dma_read(&s->dev, base, (void *)&desc, sizeof(desc));

        DBGOUT(TX, "index %d: %p : %x %x\n", s->mac_reg[TDH],
               (void *)(intptr_t)desc.buffer_addr, desc.lower.data,
               desc.upper.data);

        process_tx_desc(s, &desc);
        cause |= txdesc_writeback(s, base, &desc);

        if (++s->mac_reg[TDH] * sizeof(desc) >= s->mac_reg[TDLEN])
            s->mac_reg[TDH] = 0;
        /*
         * the following could happen only if guest sw assigns
         * bogus values to TDT/TDLEN.
         * there's nothing too intelligent we could do about this.
         */
        if (s->mac_reg[TDH] == tdh_start) {
            DBGOUT(TXERR, "TDH wraparound @%x, TDT %x, TDLEN %x\n",
                   tdh_start, s->mac_reg[TDT], s->mac_reg[TDLEN]);
            break;
        }
    }
    set_ics(s, 0, cause);
}

static int
receive_filter(E1000State *s, const uint8_t *buf, int size)
{
    static const uint8_t bcast[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    static const int mta_shift[] = {4, 3, 2, 0};
    uint32_t f, rctl = s->mac_reg[RCTL], ra[2], *rp;

    if (is_vlan_packet(s, buf) && vlan_rx_filter_enabled(s)) {
        uint16_t vid = be16_to_cpup((uint16_t *)(buf + 14));
        uint32_t vfta = le32_to_cpup((uint32_t *)(s->mac_reg + VFTA) +
                                     ((vid >> 5) & 0x7f));
        if ((vfta & (1 << (vid & 0x1f))) == 0)
            return 0;
    }

    if (rctl & E1000_RCTL_UPE)			// promiscuous
        return 1;

    if ((buf[0] & 1) && (rctl & E1000_RCTL_MPE))	// promiscuous mcast
        return 1;

    if ((rctl & E1000_RCTL_BAM) && !memcmp(buf, bcast, sizeof bcast))
        return 1;

    for (rp = s->mac_reg + RA; rp < s->mac_reg + RA + 32; rp += 2) {
        if (!(rp[1] & E1000_RAH_AV))
            continue;
        ra[0] = cpu_to_le32(rp[0]);
        ra[1] = cpu_to_le32(rp[1]);
        if (!memcmp(buf, (uint8_t *)ra, 6)) {
            DBGOUT(RXFILTER,
                   "unicast match[%d]: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   (int)(rp - s->mac_reg - RA)/2,
                   buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
            return 1;
        }
    }
    DBGOUT(RXFILTER, "unicast mismatch: %02x:%02x:%02x:%02x:%02x:%02x\n",
           buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);

    f = mta_shift[(rctl >> E1000_RCTL_MO_SHIFT) & 3];
    f = (((buf[5] << 8) | buf[4]) >> f) & 0xfff;
    if (s->mac_reg[MTA + (f >> 5)] & (1 << (f & 0x1f)))
        return 1;
    DBGOUT(RXFILTER,
           "dropping, inexact filter mismatch: %02x:%02x:%02x:%02x:%02x:%02x MO %d MTA[%d] %x\n",
           buf[0], buf[1], buf[2], buf[3], buf[4], buf[5],
           (rctl >> E1000_RCTL_MO_SHIFT) & 3, f >> 5,
           s->mac_reg[MTA + (f >> 5)]);

    return 0;
}

static void
e1000_set_link_status(VLANClientState *nc)
{
    E1000State *s = DO_UPCAST(NICState, nc, nc)->opaque;
    uint32_t old_status = s->mac_reg[STATUS];

    if (nc->link_down) {
        s->mac_reg[STATUS] &= ~E1000_STATUS_LU;
        s->phy_reg[PHY_STATUS] &= ~MII_SR_LINK_STATUS;
    } else {
        s->mac_reg[STATUS] |= E1000_STATUS_LU;
        s->phy_reg[PHY_STATUS] |= MII_SR_LINK_STATUS;
    }

    if (s->mac_reg[STATUS] != old_status)
        set_ics(s, 0, E1000_ICR_LSC);
}

static bool e1000_has_rxbufs(E1000State *s, size_t total_size)
{
    int bufs;
    /* Fast-path short packets */
    if (total_size <= s->rxbuf_size) {
        return s->mac_reg[RDH] != s->mac_reg[RDT] || !s->check_rxov;
    }
    if (s->mac_reg[RDH] < s->mac_reg[RDT]) {
        bufs = s->mac_reg[RDT] - s->mac_reg[RDH];
    } else if (s->mac_reg[RDH] > s->mac_reg[RDT] || !s->check_rxov) {
        bufs = s->mac_reg[RDLEN] /  sizeof(struct e1000_rx_desc) +
            s->mac_reg[RDT] - s->mac_reg[RDH];
    } else {
        return false;
    }
    return total_size <= bufs * s->rxbuf_size;
}

static int
e1000_can_receive(VLANClientState *nc)
{
    E1000State *s = DO_UPCAST(NICState, nc, nc)->opaque;

    return (s->mac_reg[RCTL] & E1000_RCTL_EN) && e1000_has_rxbufs(s, 1);
}

static uint64_t rx_desc_base(E1000State *s)
{
    uint64_t bah = s->mac_reg[RDBAH];
    uint64_t bal = s->mac_reg[RDBAL] & ~0xf;

    return (bah << 32) + bal;
}

static ssize_t
e1000_receive(VLANClientState *nc, const uint8_t *buf, size_t size)
{
    E1000State *s = DO_UPCAST(NICState, nc, nc)->opaque;
    struct e1000_rx_desc desc;
    dma_addr_t base;
    unsigned int n, rdt;
    uint32_t rdh_start;
    uint16_t vlan_special = 0;
    uint8_t vlan_status = 0, vlan_offset = 0;
    uint8_t min_buf[MIN_BUF_SIZE];
    size_t desc_offset;
    size_t desc_size;
    size_t total_size;

    if (!(s->mac_reg[RCTL] & E1000_RCTL_EN))
        return -1;

    /* Pad to minimum Ethernet frame length */
    if (size < sizeof(min_buf)) {
        memcpy(min_buf, buf, size);
        memset(&min_buf[size], 0, sizeof(min_buf) - size);
        buf = min_buf;
        size = sizeof(min_buf);
    }

    if (!receive_filter(s, buf, size))
        return size;

    if (vlan_enabled(s) && is_vlan_packet(s, buf)) {
        vlan_special = cpu_to_le16(be16_to_cpup((uint16_t *)(buf + 14)));
        memmove((uint8_t *)buf + 4, buf, 12);
        vlan_status = E1000_RXD_STAT_VP;
        vlan_offset = 4;
        size -= 4;
    }

    rdh_start = s->mac_reg[RDH];
    desc_offset = 0;
    total_size = size + fcs_len(s);
    if (!e1000_has_rxbufs(s, total_size)) {
            set_ics(s, 0, E1000_ICS_RXO);
            return -1;
    }
    do {
        desc_size = total_size - desc_offset;
        if (desc_size > s->rxbuf_size) {
            desc_size = s->rxbuf_size;
        }
        base = rx_desc_base(s) + sizeof(desc) * s->mac_reg[RDH];
        pci_dma_read(&s->dev, base, (void *)&desc, sizeof(desc));
        desc.special = vlan_special;
        desc.status |= (vlan_status | E1000_RXD_STAT_DD);
        if (desc.buffer_addr) {
            if (desc_offset < size) {
                size_t copy_size = size - desc_offset;
                if (copy_size > s->rxbuf_size) {
                    copy_size = s->rxbuf_size;
                }
                pci_dma_write(&s->dev, le64_to_cpu(desc.buffer_addr),
                                 (void *)(buf + desc_offset + vlan_offset),
                                 copy_size);
            }
            desc_offset += desc_size;
            desc.length = cpu_to_le16(desc_size);
            if (desc_offset >= total_size) {
                desc.status |= E1000_RXD_STAT_EOP | E1000_RXD_STAT_IXSM;
            } else {
                /* Guest zeroing out status is not a hardware requirement.
                   Clear EOP in case guest didn't do it. */
                desc.status &= ~E1000_RXD_STAT_EOP;
            }
        } else { // as per intel docs; skip descriptors with null buf addr
            DBGOUT(RX, "Null RX descriptor!!\n");
        }
        pci_dma_write(&s->dev, base, (void *)&desc, sizeof(desc));

        if (++s->mac_reg[RDH] * sizeof(desc) >= s->mac_reg[RDLEN])
            s->mac_reg[RDH] = 0;
        s->check_rxov = 1;
        /* see comment in start_xmit; same here */
        if (s->mac_reg[RDH] == rdh_start) {
            DBGOUT(RXERR, "RDH wraparound @%x, RDT %x, RDLEN %x\n",
                   rdh_start, s->mac_reg[RDT], s->mac_reg[RDLEN]);
            set_ics(s, 0, E1000_ICS_RXO);
            return -1;
        }
    } while (desc_offset < total_size);

    s->mac_reg[GPRC]++;
    s->mac_reg[TPR]++;
    /* TOR - Total Octets Received:
     * This register includes bytes received in a packet from the <Destination
     * Address> field through the <CRC> field, inclusively.
     */
    n = s->mac_reg[TORL] + size + /* Always include FCS length. */ 4;
    if (n < s->mac_reg[TORL])
        s->mac_reg[TORH]++;
    s->mac_reg[TORL] = n;

    n = E1000_ICS_RXT0;
    if ((rdt = s->mac_reg[RDT]) < s->mac_reg[RDH])
        rdt += s->mac_reg[RDLEN] / sizeof(desc);
    if (((rdt - s->mac_reg[RDH]) * sizeof(desc)) <= s->mac_reg[RDLEN] >>
        s->rxbuf_min_shift)
        n |= E1000_ICS_RXDMT0;

    set_ics(s, 0, n);

    return size;
}

static uint32_t
mac_readreg(E1000State *s, int index)
{
    return s->mac_reg[index];
}

static uint32_t
mac_icr_read(E1000State *s, int index)
{
    uint32_t ret = s->mac_reg[ICR];

    DBGOUT(INTERRUPT, "ICR read: %x\n", ret);
    set_interrupt_cause(s, 0, 0);
    return ret;
}

static uint32_t
mac_read_clr4(E1000State *s, int index)
{
    uint32_t ret = s->mac_reg[index];

    s->mac_reg[index] = 0;
    return ret;
}

static uint32_t
mac_read_clr8(E1000State *s, int index)
{
    uint32_t ret = s->mac_reg[index];

    s->mac_reg[index] = 0;
    s->mac_reg[index-1] = 0;
    return ret;
}

static void
mac_writereg(E1000State *s, int index, uint32_t val)
{
    s->mac_reg[index] = val;
}

static void
set_rdt(E1000State *s, int index, uint32_t val)
{
    s->check_rxov = 0;
    s->mac_reg[index] = val & 0xffff;
}

static void
set_16bit(E1000State *s, int index, uint32_t val)
{
    s->mac_reg[index] = val & 0xffff;
}

static void
set_dlen(E1000State *s, int index, uint32_t val)
{
    s->mac_reg[index] = val & 0xfff80;
}

static void
set_tctl(E1000State *s, int index, uint32_t val)
{
    s->mac_reg[index] = val;
    s->mac_reg[TDT] &= 0xffff;
    start_xmit(s);
}

static void
set_icr(E1000State *s, int index, uint32_t val)
{
    DBGOUT(INTERRUPT, "set_icr %x\n", val);
    set_interrupt_cause(s, 0, s->mac_reg[ICR] & ~val);
}

static void
set_imc(E1000State *s, int index, uint32_t val)
{
    s->mac_reg[IMS] &= ~val;
    set_ics(s, 0, 0);
}

static void
set_ims(E1000State *s, int index, uint32_t val)
{
    s->mac_reg[IMS] |= val;
    set_ics(s, 0, 0);
}

#define getreg(x)	[x] = mac_readreg
static uint32_t (*macreg_readops[])(E1000State *, int) = {
    getreg(PBA),	getreg(RCTL),	getreg(TDH),	getreg(TXDCTL),
    getreg(WUFC),	getreg(TDT),	getreg(CTRL),	getreg(LEDCTL),
    getreg(MANC),	getreg(MDIC),	getreg(SWSM),	getreg(STATUS),
    getreg(TORL),	getreg(TOTL),	getreg(IMS),	getreg(TCTL),
    getreg(RDH),	getreg(RDT),	getreg(VET),	getreg(ICS),
    getreg(TDBAL),	getreg(TDBAH),	getreg(RDBAH),	getreg(RDBAL),
    getreg(TDLEN),	getreg(RDLEN),

    [TOTH] = mac_read_clr8,	[TORH] = mac_read_clr8,	[GPRC] = mac_read_clr4,
    [GPTC] = mac_read_clr4,	[TPR] = mac_read_clr4,	[TPT] = mac_read_clr4,
    [ICR] = mac_icr_read,	[EECD] = get_eecd,	[EERD] = flash_eerd_read,
    [CRCERRS ... MPC] = &mac_readreg,
    [RA ... RA+31] = &mac_readreg,
    [MTA ... MTA+127] = &mac_readreg,
    [VFTA ... VFTA+127] = &mac_readreg,
};
enum { NREADOPS = ARRAY_SIZE(macreg_readops) };

#define putreg(x)	[x] = mac_writereg
static void (*macreg_writeops[])(E1000State *, int, uint32_t) = {
    putreg(PBA),	putreg(EERD),	putreg(SWSM),	putreg(WUFC),
    putreg(TDBAL),	putreg(TDBAH),	putreg(TXDCTL),	putreg(RDBAH),
    putreg(RDBAL),	putreg(LEDCTL), putreg(VET),
    [TDLEN] = set_dlen,	[RDLEN] = set_dlen,	[TCTL] = set_tctl,
    [TDT] = set_tctl,	[MDIC] = set_mdic,	[ICS] = set_ics,
    [TDH] = set_16bit,	[RDH] = set_16bit,	[RDT] = set_rdt,
    [IMC] = set_imc,	[IMS] = set_ims,	[ICR] = set_icr,
    [EECD] = set_eecd,	[RCTL] = set_rx_control, [CTRL] = set_ctrl,
    [RA ... RA+31] = &mac_writereg,
    [MTA ... MTA+127] = &mac_writereg,
    [VFTA ... VFTA+127] = &mac_writereg,
};
enum { NWRITEOPS = ARRAY_SIZE(macreg_writeops) };

static void
e1000_mmio_write(void *opaque, target_phys_addr_t addr, uint64_t val,
                 unsigned size)
{
    E1000State *s = opaque;
    unsigned int index = (addr & 0x1ffff) >> 2;

    if (index < NWRITEOPS && macreg_writeops[index]) {
        macreg_writeops[index](s, index, val);
    } else if (index < NREADOPS && macreg_readops[index]) {
        DBGOUT(MMIO, "e1000_mmio_writel RO %x: 0x%04"PRIx64"\n", index<<2, val);
    } else {
        DBGOUT(UNKNOWN, "MMIO unknown write addr=0x%08x,val=0x%08"PRIx64"\n",
               index<<2, val);
    }
}

static uint64_t
e1000_mmio_read(void *opaque, target_phys_addr_t addr, unsigned size)
{
    E1000State *s = opaque;
    unsigned int index = (addr & 0x1ffff) >> 2;

    if (index < NREADOPS && macreg_readops[index])
    {
        return macreg_readops[index](s, index);
    }
    DBGOUT(UNKNOWN, "MMIO unknown read addr=0x%08x\n", index<<2);
    return 0;
}

static const MemoryRegionOps e1000_mmio_ops = {
    .read = e1000_mmio_read,
    .write = e1000_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

static uint64_t e1000_io_read(void *opaque, target_phys_addr_t addr,
                              unsigned size)
{
    E1000State *s = opaque;

    (void)s;
    return 0;
}

static void e1000_io_write(void *opaque, target_phys_addr_t addr,
                           uint64_t val, unsigned size)
{
    E1000State *s = opaque;

    (void)s;
}

static const MemoryRegionOps e1000_io_ops = {
    .read = e1000_io_read,
    .write = e1000_io_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static const uint16_t e1000_eeprom_template[64] = {
    0x0000, 0x0000, 0x0000, 0x0000,      0xffff, 0x0000,      0x0000, 0x0000,
    0x3000, 0x1000, 0x6403, E1000_DEVID, 0x8086, E1000_DEVID, 0x8086, 0x3040,
    0x0008, 0x2000, 0x7e14, 0x0048,      0x1000, 0x00d8,      0x0000, 0x2700,
    0x6cc9, 0x3150, 0x0722, 0x040b,      0x0984, 0x0000,      0xc000, 0x0706,
    0x1008, 0x0000, 0x0f04, 0x7fff,      0x4d01, 0xffff,      0xffff, 0xffff,
    0xffff, 0xffff, 0xffff, 0xffff,      0xffff, 0xffff,      0xffff, 0xffff,
    0x0100, 0x4000, 0x121c, 0xffff,      0xffff, 0xffff,      0xffff, 0xffff,
    0xffff, 0xffff, 0xffff, 0xffff,      0xffff, 0xffff,      0xffff, 0x0000,
};

static const uint16_t phy_reg_init[] = {
    [PHY_CTRL] = 0x1140,			[PHY_STATUS] = 0x796d, // link initially up
    [PHY_ID1] = 0x141,				[PHY_ID2] = PHY_ID2_INIT,
    [PHY_1000T_CTRL] = 0x0e00,			[M88E1000_PHY_SPEC_CTRL] = 0x360,
    [M88E1000_EXT_PHY_SPEC_CTRL] = 0x0d60,	[PHY_AUTONEG_ADV] = 0xde1,
    [PHY_LP_ABILITY] = 0x1e0,			[PHY_1000T_STATUS] = 0x3c00,
    [M88E1000_PHY_SPEC_STATUS] = 0xac00,
};

static const uint32_t mac_reg_init[] = {
    [PBA] =     0x00100030,
    [LEDCTL] =  0x602,
    [CTRL] =    E1000_CTRL_SWDPIN2 | E1000_CTRL_SWDPIN0 |
                E1000_CTRL_SPD_1000 | E1000_CTRL_SLU,
    [STATUS] =  0x80000000 | E1000_STATUS_GIO_MASTER_ENABLE |
                E1000_STATUS_ASDV | E1000_STATUS_MTXCKOK |
                E1000_STATUS_SPEED_1000 | E1000_STATUS_FD |
                E1000_STATUS_LU,
    [MANC] =    E1000_MANC_EN_MNG2HOST | E1000_MANC_RCV_TCO_EN |
                E1000_MANC_ARP_EN | E1000_MANC_0298_EN |
                E1000_MANC_RMCP_EN,
};

/* PCI interface */
static void
e1000_mmio_setup(E1000State *d)
{
    int i;
    const uint32_t excluded_regs[] = {
        E1000_MDIC, E1000_ICR, E1000_ICS, E1000_IMS,
        E1000_IMC, E1000_TCTL, E1000_TDT, PNPMMIO_SIZE
    };

    memory_region_init_io(&d->mmio, &e1000_mmio_ops, d, "e1000-mmio",
                          PNPMMIO_SIZE);
    memory_region_add_coalescing(&d->mmio, 0, excluded_regs[0]);
    for (i = 0; excluded_regs[i] != PNPMMIO_SIZE; i++)
        memory_region_add_coalescing(&d->mmio, excluded_regs[i] + 4,
                                     excluded_regs[i+1] - excluded_regs[i] - 4);
    memory_region_init_io(&d->io, &e1000_io_ops, d, "e1000-io", IOPORT_SIZE);
}

static void
e1000_cleanup(VLANClientState *nc)
{
    E1000State *s = DO_UPCAST(NICState, nc, nc)->opaque;

    s->nic = NULL;
}

static int
pci_e1000_uninit(PCIDevice *dev)
{
    E1000State *d = DO_UPCAST(E1000State, dev, dev);

    memory_region_destroy(&d->mmio);
    memory_region_destroy(&d->io);
    qemu_del_vlan_client(&d->nic->nc);
    return 0;
}

static void e1000_reset(void *opaque)
{
    E1000State *d = opaque;

    memset(d->phy_reg, 0, sizeof d->phy_reg);
    memmove(d->phy_reg, phy_reg_init, sizeof phy_reg_init);
    memset(d->mac_reg, 0, sizeof d->mac_reg);
    memmove(d->mac_reg, mac_reg_init, sizeof mac_reg_init);
    d->rxbuf_min_shift = 1;
    memset(&d->tx, 0, sizeof d->tx);
}

static NetClientInfo net_e1000_info = {
    .type = NET_CLIENT_TYPE_NIC,
    .size = sizeof(NICState),
    .can_receive = e1000_can_receive,
    .receive = e1000_receive,
    .cleanup = e1000_cleanup,
    .link_status_changed = e1000_set_link_status,
};

static int pci_e1000_init(PCIDevice *pci_dev)
{
    E1000State *d = DO_UPCAST(E1000State, dev, pci_dev);
    uint8_t *pci_conf;
    uint16_t checksum = 0;
    int i;
    uint8_t *macaddr;

    pci_conf = d->dev.config;

    /* TODO: RST# value should be 0, PCI spec 6.2.4 */
    pci_conf[PCI_CACHE_LINE_SIZE] = 0x10;

    pci_conf[PCI_INTERRUPT_PIN] = 1; /* interrupt pin A */

    e1000_mmio_setup(d);

    pci_register_bar(&d->dev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &d->mmio);

    pci_register_bar(&d->dev, 1, PCI_BASE_ADDRESS_SPACE_IO, &d->io);

    memmove(d->eeprom_data, e1000_eeprom_template,
        sizeof e1000_eeprom_template);
    qemu_macaddr_default_if_unset(&d->conf.macaddr);
    macaddr = d->conf.macaddr.a;
    for (i = 0; i < 3; i++)
        d->eeprom_data[i] = (macaddr[2*i+1]<<8) | macaddr[2*i];
    for (i = 0; i < EEPROM_CHECKSUM_REG; i++)
        checksum += d->eeprom_data[i];
    checksum = (uint16_t) EEPROM_SUM - checksum;
    d->eeprom_data[EEPROM_CHECKSUM_REG] = checksum;

    d->nic = qemu_new_nic(&net_e1000_info, &d->conf,
                          d->dev.qdev.info->name, d->dev.qdev.id, d);

    qemu_format_nic_info_str(&d->nic->nc, macaddr);

    add_boot_device_path(d->conf.bootindex, &pci_dev->qdev, "/ethernet-phy@0");

    return 0;
}

static void qdev_e1000_reset(DeviceState *dev)
{
    E1000State *d = DO_UPCAST(E1000State, dev.qdev, dev);
    e1000_reset(d);
}

static PCIDeviceInfo e1000_info = {
    .qdev.name  = "e1000",
    .qdev.desc  = "Intel Gigabit Ethernet",
    .qdev.size  = sizeof(E1000State),
    .qdev.reset = qdev_e1000_reset,
    .init       = pci_e1000_init,
    .exit       = pci_e1000_uninit,
    .romfile    = "pxe-e1000.rom",
    .vendor_id  = PCI_VENDOR_ID_INTEL,
    .device_id  = E1000_DEVID,
    .revision   = 0x03,
    .class_id   = PCI_CLASS_NETWORK_ETHERNET,
    .qdev.props = (Property[]) {
        DEFINE_NIC_PROPERTIES(E1000State, conf),
        DEFINE_PROP_END_OF_LIST(),
    }
};

static void e1000_register_devices(void)
{
    pci_qdev_register(&e1000_info);
}

device_init(e1000_register_devices)
