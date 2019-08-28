##############################################################################
#  Copyright (c) 2019 Intel Corporation
# 
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
# 
#      http://www.apache.org/licenses/LICENSE-2.0
# 
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
##############################################################################
#    File Abstract: 
#    Dumps a ton of data about an Ethernet port by talking to the driver the same
#    way ethtool utility would.  For Linux and Python 3 only
##############################################################################
#!/usr/bin/env python
import socket
import array
import fcntl
import struct
import array
import sys
from pprint import pprint as pprint

__author__      = "Patrick.Kutch@gmail.com"

SIOCETHTOOL = 0x8946
ETHTOOL_GSTRINGS = 0x0000001b
ETHTOOL_GSSET_INFO = 0x00000037
ETHTOOL_GSTATS = 0x0000001d
ETH_SS_STATS = 0x01
ETH_SS_PRIV_FLAGS = 0x02
ETH_GSTRING_LEN = 32
ETHTOOL_GDRVINFO = 0x00000003
ETHTOOL_GCOALESCE =	0x0000000e 

ETHTOOL_FWVERS_LEN	= 32
ETHTOOL_BUSINFO_LEN	= 32
ETHTOOL_EROMVERS_LEN = 32

verStr = "1.0 [08.28.19]"

'''
## Pack defintions for the various structures that could be used, based upon ethtool.h
ethtool_cmd_struct = array.array('B', struct.pack('IIIHBBBBBBIIHBBI2I',0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 * 2))
cmd,supported,advertising,speed,duplex,port,phy_address,transceiver,autoneg,mdio_support,maxtxpkt,maxrxpkt,speed_hi,eth_tp_mdix,eth_tp_mdix_ctrl,lp_advertising,reserved = struct.unpack("IIIHBBBBBBIIHBBI2I",ethtool_cmd_struct)
ethtool_drvinfo_struct = array.array('B', struct.pack('I32s32s32s32s32s12sIIIII',0,b'\x00' * 32,b'\x00' * 32,b'\x00' * 32,b'\x00' * 32,b'\x00' * 32,b'\x00' * 12,0,0,0,0,0))
cmd,driver,version,fw_version,bus_info,erom_version,reserved2,n_priv_flags,n_stats,testinfo_len,eedump_len,regdump_len = struct.unpack("I32s32s32s32s32s12sIIIII",ethtool_drvinfo_struct)
ethtool_wolinfo_struct = array.array('B', struct.pack('III6B',0,0,0,0 * 6))
cmd,supported,wolopts,sopass = struct.unpack("III6B",ethtool_wolinfo_struct)
ethtool_value_struct = array.array('B', struct.pack('II',0,0))
cmd,data = struct.unpack("II",ethtool_value_struct)
ethtool_tunable_struct = array.array('B', struct.pack('IIIIP',0,0,0,0,0))
cmd,id,type_id,len,data = struct.unpack("IIIIP",ethtool_tunable_struct)
ethtool_regs_struct = array.array('B', struct.pack('IIIB',0,0,0,0))
cmd,version,len,data = struct.unpack("IIIB",ethtool_regs_struct)
ethtool_eeprom_struct = array.array('B', struct.pack('IIIIB',0,0,0,0,0))
cmd,magic,offset,len,data = struct.unpack("IIIIB",ethtool_eeprom_struct)
ethtool_eee_struct = array.array('B', struct.pack('IIIIIIII2I',0,0,0,0,0,0,0,0,0 * 2))
cmd,supported,advertised,lp_advertised,eee_active,eee_enabled,tx_lpi_enabled,tx_lpi_timer,reserved = struct.unpack("IIIIIIII2I",ethtool_eee_struct)
ethtool_modinfo_struct = array.array('B', struct.pack('III8I',0,0,0,0 * 8))
cmd,type,eeprom_len,reserved = struct.unpack("III8I",ethtool_modinfo_struct)
ethtool_coalesce_struct = array.array('B', struct.pack('IIIIIIIIIIIIIIIIIIIIIII',0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0))
cmd,rx_coalesce_usecs,rx_max_coalesced_frames,rx_coalesce_usecs_irq,rx_max_coalesced_frames_irq,tx_coalesce_usecs,tx_max_coalesced_frames,tx_coalesce_usecs_irq,tx_max_coalesced_frames_irq,stats_block_coalesce_usecs,use_adaptive_rx_coalesce,use_adaptive_tx_coalesce,pkt_rate_low,rx_coalesce_usecs_low,rx_max_coalesced_frames_low,tx_coalesce_usecs_low,tx_max_coalesced_frames_low,pkt_rate_high,rx_coalesce_usecs_high,rx_max_coalesced_frames_high,tx_coalesce_usecs_high,tx_max_coalesced_frames_high,rate_sample_interval = struct.unpack("IIIIIIIIIIIIIIIIIIIIIII",ethtool_coalesce_struct)
ethtool_ringparam_struct = array.array('B', struct.pack('IIIIIIIII',0,0,0,0,0,0,0,0,0))
cmd,rx_max_pending,rx_mini_max_pending,rx_jumbo_max_pending,tx_max_pending,rx_pending,rx_mini_pending,rx_jumbo_pending,tx_pending = struct.unpack("IIIIIIIII",ethtool_ringparam_struct)
ethtool_channels_struct = array.array('B', struct.pack('IIIIIIIII',0,0,0,0,0,0,0,0,0))
cmd,max_rx,max_tx,max_other,max_combined,rx_count,tx_count,other_count,combined_count = struct.unpack("IIIIIIIII",ethtool_channels_struct)
ethtool_pauseparam_struct = array.array('B', struct.pack('IIII',0,0,0,0))
cmd,autoneg,rx_pause,tx_pause = struct.unpack("IIII",ethtool_pauseparam_struct)
ethtool_gstrings_struct = array.array('B', struct.pack('IIIB',0,0,0,0))
cmd,string_set,len,data = struct.unpack("IIIB",ethtool_gstrings_struct)
ethtool_sset_info_struct = array.array('B', struct.pack('IIQI',0,0,0,0))
cmd,reserved,sset_mask,data = struct.unpack("IIQI",ethtool_sset_info_struct)
ethtool_test_struct = array.array('B', struct.pack('IIIIQ',0,0,0,0,0))
cmd,flags,reserved,len,data = struct.unpack("IIIIQ",ethtool_test_struct)
ethtool_stats_struct = array.array('B', struct.pack('IIQ',0,0,0))
cmd,n_stats,data = struct.unpack("IIQ",ethtool_stats_struct)
ethtool_perm_addr_struct = array.array('B', struct.pack('IIB',0,0,0))
cmd,size,data = struct.unpack("IIB",ethtool_perm_addr_struct)
ethtool_rxnfc::union _struct = array.array('B', struct.pack('II',0,0))
rule_cnt,rss_context = struct.unpack("II",ethtool_rxnfc::union _struct)
ethtool_rxfh_indir_struct = array.array('B', struct.pack('III',0,0,0))
cmd,size,ring_index = struct.unpack("III",ethtool_rxfh_indir_struct)
ethtool_rxfh_struct = array.array('B', struct.pack('IIIIB3BII',0,0,0,0,0,0 * 3,0,0))
cmd,rss_context,indir_size,key_size,hfunc,rsvd8,rsvd32,rss_config = struct.unpack("IIIIB3BII",ethtool_rxfh_struct)
ethtool_flash_struct = array.array('B', struct.pack('II128s',0,0,b'\x00' * 128))
cmd,region,data = struct.unpack("II128s",ethtool_flash_struct)
ethtool_dump_struct = array.array('B', struct.pack('IIIIB',0,0,0,0,0))
cmd,version,flag,len,data = struct.unpack("IIIIB",ethtool_dump_struct)
ethtool_get_features_block_struct = array.array('B', struct.pack('IIII',0,0,0,0))
available,requested,active,never_changed = struct.unpack("IIII",ethtool_get_features_block_struct)
ethtool_set_features_block_struct = array.array('B', struct.pack('II',0,0))
valid,requested = struct.unpack("II",ethtool_set_features_block_struct)
ethtool_ts_info_struct = array.array('B', struct.pack('IIiI3II3I',0,0,0,0,0 * 3,0,0 * 3))
cmd,so_timestamping,phc_index,tx_types,tx_reserved,rx_filters,rx_reserved = struct.unpack("IIiI3II3I",ethtool_ts_info_struct)
ethtool_fecparam_struct = array.array('B', struct.pack('IIII',0,0,0,0))
cmd,active_fec,fec,reserved = struct.unpack("IIII",ethtool_fecparam_struct)
ethtool_link_settings_struct = array.array('B', struct.pack('IIBBBBBBBbB3B7II',0,0,0,0,0,0,0,0,0,0,0,0 * 3,0 * 7,0))
cmd,speed,duplex,port,phy_address,autoneg,mdio_support,eth_tp_mdix,eth_tp_mdix_ctrl,link_mode_masks_nwords,transceiver,reserved1,reserved,link_mode_masks = struct.unpack("IIBBBBBBBbB3B7II",ethtool_link_settings_struct)
'''

## Strings come in with 0x00 padding, strip it
def trimString(inpString):
    retStr=""
    
    for index, c in enumerate(inpString.decode('utf-8')):
        if 0 == inpString[index] : break
        retStr += str(c)
        
    return retStr
    

class PortDumper(object):
    def __init__(self, ifName):
        self._maxCheckIndex = 200
        self.__interfaceName = ifName
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)

    def _send_ioctl(self, data):
        sendData = struct.pack('16sP', self.__interfaceName.encode("utf-8"), data.buffer_info()[0])
        return fcntl.ioctl(self._sock.fileno(), SIOCETHTOOL, sendData)
        
    def get_StringSet(self, set_id):
        ## Get how many strings in this set
        ethtool_sset_info_struct = array.array('B', struct.pack("IIQI", ETHTOOL_GSSET_INFO, 0, 1 << set_id, 0))
        self._send_ioctl(ethtool_sset_info_struct)

        set_mask, set_len = struct.unpack("8xQI", ethtool_sset_info_struct)
        if set_mask == 0:
            set_len = 0

        # Go get the strings for this set

        ethtool_gstrings_struct = array.array("B", struct.pack("III", ETHTOOL_GSTRINGS, set_id, set_len))

        #ethtool_gstrings_struct.extend(c'\x00' * int(set_len) * int(ETH_GSTRING_LEN))
        ethtool_gstrings_struct.extend(bytearray(int(set_len) * int(ETH_GSTRING_LEN)))
        self._send_ioctl(ethtool_gstrings_struct)
        
        for index in range(set_len):
            offset = 12 + ETH_GSTRING_LEN * index
            statString = bytearray(ethtool_gstrings_struct[offset:offset+ETH_GSTRING_LEN]).partition(b'\x00')[0].decode("utf-8")
            yield statString

    def get_stats(self):
        # go get the set strings
        strings = list(self.get_StringSet(ETH_SS_STATS))
        n_stats = len(strings)

        retList=[]
        retList.append("--- Statistics ---")

        #go get the actual stats
        ethtool_stats_struct = array.array("B", struct.pack("II", ETHTOOL_GSTATS, n_stats))
        ethtool_stats_struct.extend(bytearray(struct.pack('Q', 0) * n_stats))
        self._send_ioctl(ethtool_stats_struct)
        for i in range(n_stats):
            offset = 8 + 8 * i
            value = struct.unpack('Q', ethtool_stats_struct[offset:offset+8])[0]
            retList.append((strings[i], value))

        return retList
            
    def get_stats_general(self,what,stringSet,description):
        # go get the set strings
        retData=[]
        retData.append(description)

        try:
            strings = list(self.get_StringSet(stringSet))
            n_stats = len(strings)
            print(strings)

            #go get the actual stats
            ethtool_stats_struct = array.array("B", struct.pack("II", what, n_stats))
            ethtool_stats_struct.extend(struct.pack('Q', 0) * n_stats)
            self._send_ioctl(ethtool_stats_struct)
            pprint(ethtool_stats_struct)
            for index in range(n_stats):
                offset = 8 + 8 * index
                dataBlock = ethtool_stats_struct[offset:offset+8]
                value = struct.unpack('Q', dataBlock)[0]        
                if len(strings[index]) > 0:
                    retData.append((strings[index], value))
                
        except Exception as ex:
            retData=[]
        
        return retData

    def getDriverInfo(self):
        # struct ethtool_drvinfo {
        # __u32	cmd;                                        
        # char	driver[32];                                 
        # char	version[32];                                
        # char	fw_version[ETHTOOL_FWVERS_LEN];             
        # char	bus_info[ETHTOOL_BUSINFO_LEN];              
        # char	erom_version[ETHTOOL_EROMVERS_LEN];         
        # char	reserved2[12];                              
        # __u32	n_priv_flags;                               
        # __u32	n_stats;                                    
        # __u32	testinfo_len;                               
        # __u32	eedump_len;                                 
        # __u32	regdump_len;                                
        # };
                                                               

        ethtool_drvinfo_struct = array.array('B', struct.pack('I32s32s32s32s32s12sIIIII',ETHTOOL_GDRVINFO,b'\x00' * 32,b'\x00' * 32,b'\x00' * 32,b'\x00' * 32,b'\x00' * 32,b'\x00' * 12,0,0,0,0,0))
        self._send_ioctl(ethtool_drvinfo_struct)

        cmd,driver,version,fw_version,bus_info,erom_version,reserved2,n_priv_flags,n_stats,testinfo_len,eedump_len,regdump_len = struct.unpack("I32s32s32s32s32s12sIIIII",ethtool_drvinfo_struct)
        
        driverInfo=[]

        driverInfo.append("--- ethtool_drvinfo ---")
        driverInfo.append(("Driver Name",trimString(driver)))
        driverInfo.append(("Driver Version",trimString(version)))
        driverInfo.append(("FW Version",trimString(fw_version)))
        driverInfo.append(("Bus Info",trimString(bus_info)))
        driverInfo.append(("EEPROM Version",trimString(erom_version)))
        driverInfo.append(("Num Priv Flags", n_priv_flags))
        
        #pprint(driverInfo)
        
        return driverInfo
        
    def getCoalesceInfo(self):
        # struct ethtool_coalesce {
            # __u32	cmd;
            # __u32	rx_coalesce_usecs;
            # __u32	rx_max_coalesced_frames;
            # __u32	rx_coalesce_usecs_irq;
            # __u32	rx_max_coalesced_frames_irq;
            # __u32	tx_coalesce_usecs;
            # __u32	tx_max_coalesced_frames;
            # __u32	tx_coalesce_usecs_irq;
            # __u32	tx_max_coalesced_frames_irq;
            # __u32	stats_block_coalesce_usecs;
            # __u32	use_adaptive_rx_coalesce;
            # __u32	use_adaptive_tx_coalesce;
            # __u32	pkt_rate_low;
            # __u32	rx_coalesce_usecs_low;
            # __u32	rx_max_coalesced_frames_low;
            # __u32	tx_coalesce_usecs_low;
            # __u32	tx_max_coalesced_frames_low;
            # __u32	pkt_rate_high;
            # __u32	rx_coalesce_usecs_high;
            # __u32	rx_max_coalesced_frames_high;
            # __u32	tx_coalesce_usecs_high;
            # __u32	tx_max_coalesced_frames_high;
            # __u32	rate_sample_interval;
        # };    

        ethtool_coalesce_struct = array.array('B', struct.pack('IIIIIIIIIIIIIIIIIIIIIII',ETHTOOL_GCOALESCE,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0))
        self._send_ioctl(ethtool_coalesce_struct)
        cmd,rx_coalesce_usecs,rx_max_coalesced_frames,rx_coalesce_usecs_irq,rx_max_coalesced_frames_irq,tx_coalesce_usecs,tx_max_coalesced_frames,tx_coalesce_usecs_irq,tx_max_coalesced_frames_irq,stats_block_coalesce_usecs,use_adaptive_rx_coalesce,use_adaptive_tx_coalesce,pkt_rate_low,rx_coalesce_usecs_low,rx_max_coalesced_frames_low,tx_coalesce_usecs_low,tx_max_coalesced_frames_low,pkt_rate_high,rx_coalesce_usecs_high,rx_max_coalesced_frames_high,tx_coalesce_usecs_high,tx_max_coalesced_frames_high,rate_sample_interval = struct.unpack("IIIIIIIIIIIIIIIIIIIIIII",ethtool_coalesce_struct)
        

        coalesceInfo=[]
        coalesceInfo.append("--- ethtool_coalesce ---")
        coalesceInfo.append(("rx_coalesce_usecs",rx_coalesce_usecs))
        coalesceInfo.append(("rx_max_coalesced_frames",rx_max_coalesced_frames))
        coalesceInfo.append(("rx_max_coalesced_frames",rx_max_coalesced_frames))
        coalesceInfo.append(("rx_max_coalesced_frames_irq",rx_max_coalesced_frames_irq))
        coalesceInfo.append(("rx_max_coalesced_frames_irq",rx_max_coalesced_frames_irq))
        coalesceInfo.append(("tx_max_coalesced_frames",tx_max_coalesced_frames))
        coalesceInfo.append(("tx_coalesce_usecs_irq",tx_coalesce_usecs_irq))
        coalesceInfo.append(("tx_max_coalesced_frames_irq",tx_max_coalesced_frames_irq))
        coalesceInfo.append(("stats_block_coalesce_usecs",stats_block_coalesce_usecs))
        coalesceInfo.append(("use_adaptive_rx_coalesce",use_adaptive_rx_coalesce))
        coalesceInfo.append(("use_adaptive_tx_coalesce",use_adaptive_tx_coalesce))
        coalesceInfo.append(("pkt_rate_low",pkt_rate_low))
        coalesceInfo.append(("rx_coalesce_usecs_low",rx_coalesce_usecs_low))
        coalesceInfo.append(("rx_max_coalesced_frames_low",rx_max_coalesced_frames_low))
        coalesceInfo.append(("tx_coalesce_usecs_low",tx_coalesce_usecs_low))
        coalesceInfo.append(("tx_max_coalesced_frames_low",tx_max_coalesced_frames_low))
        coalesceInfo.append(("pkt_rate_high",pkt_rate_high))
        coalesceInfo.append(("rx_coalesce_usecs_high",rx_coalesce_usecs_high))
        coalesceInfo.append(("rx_max_coalesced_frames_high",rx_max_coalesced_frames_high))
        coalesceInfo.append(("tx_coalesce_usecs_high",tx_coalesce_usecs_high))
        coalesceInfo.append(("tx_max_coalesced_frames_high",tx_max_coalesced_frames_high))
        coalesceInfo.append(("rate_sample_interval",rate_sample_interval))

        return coalesceInfo

    def getLinkInfo(self):
        '''
            struct ethtool_link_settings {
                __u32	cmd;
                __u32	speed;
                __u8	duplex;
                __u8	port;
                __u8	phy_address;
                __u8	autoneg;
                __u8	mdio_support;
                __u8	eth_tp_mdix;
                __u8	eth_tp_mdix_ctrl;
                __s8	link_mode_masks_nwords;
                __u8	transceiver;
                __u8	reserved1[3];
                __u32	reserved[7];
                __u32	link_mode_masks[0];
                /* layout of link_mode_masks fields:
                * __u32 map_supported[link_mode_masks_nwords];
                * __u32 map_advertising[link_mode_masks_nwords];
                * __u32 map_lp_advertising[link_mode_masks_nwords];
                */
            };
        '''        
        linkInfo=[]
        ethtool_link_settings_struct = array.array('B', struct.pack('IIBBBBBBBbB3B7II',0x0000004c,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0))
        self._send_ioctl(ethtool_link_settings_struct)
        unpackStr = "IBBBBBBBbB"
        speed,duplex,port,phy_address,autoneg,mdio_support,eth_tp_mdix,eth_tp_mdix_ctrl,link_mode_masks_nwords,transceiver = struct.unpack(unpackStr,ethtool_link_settings_struct[4:17])

        linkInfo.append("--- ethtool_link_settings ---") 
        linkInfo.append(('speed',speed))
        linkInfo.append(('duplex',duplex))
        linkInfo.append(('port',port))
        linkInfo.append(('phy_address',phy_address))
        linkInfo.append(('autoneg',autoneg))
        linkInfo.append(('mdio_support',mdio_support))
        linkInfo.append(('eth_tp_mdix',eth_tp_mdix))
        linkInfo.append(('eth_tp_mdix_ctrl',eth_tp_mdix_ctrl))
        #linkInfo.append(('link_mode_masks_nwords',link_mode_masks_nwords)) # Docs say to ignore
        linkInfo.append(('transceiver',transceiver))

        return linkInfo

    def getEneryEfficientEthernetInfo(self):
        eeeInfo=[]
        eeeInfo.append("--- energy_efficient_ethernet ---") 
        try:
            ethtool_eee_struct = array.array('B', struct.pack('IIIIIIII2I',0x00000044,0,0,0,0,0,0,0,0,0))
            self._send_ioctl(ethtool_eee_struct)
            supported,advertised,lp_advertised,eee_active,eee_enabled,tx_lpi_enabled,tx_lpi_timer,reserved = struct.unpack("IIIIIII2I",ethtool_eee_struct[4:])

            eeeInfo.append(('supported',supported))
            eeeInfo.append(('advertised',advertised))
            eeeInfo.append(('lp_advertised',lp_advertised))
            eeeInfo.append(('eee_active',eee_active))
            eeeInfo.append(('eee_enabled',eee_enabled))
            eeeInfo.append(('tx_lpi_enabled',tx_lpi_enabled))
            eeeInfo.append(('tx_lpi_timer',tx_lpi_timer))
            eeeInfo.append(('supported',supported))

        except:
            eeeInfo.append(("not supported","not supported")) 
        
        return eeeInfo

    def getEthtoolValue(self,what,description):
        retVal=[]
        try:
            ethtool_value_struct = array.array('B', struct.pack('II',what,0))
            self._send_ioctl(ethtool_value_struct)
            cmd,data = struct.unpack("II",ethtool_value_struct)    
            if 1 == data:
                data = 'true'
            elif 0 == data:
                data = 'false'
            retVal.append((description,data))
        except:
            retVal.append((description,"Not Supported"))

        return retVal

    def getRingParameters(self):
        ringInfo=[]
        ringInfo.append("--- ring parameters ---") 
        try:
            ethtool_ringparam_struct = array.array('B', struct.pack('IIIIIIIII',0x00000010,0,0,0,0,0,0,0,0))
            self._send_ioctl(ethtool_ringparam_struct)
            cmd,rx_max_pending,rx_mini_max_pending,rx_jumbo_max_pending,tx_max_pending,rx_pending,rx_mini_pending,rx_jumbo_pending,tx_pending = struct.unpack("IIIIIIIII",ethtool_ringparam_struct)

            ringInfo.append(('rx_max_pending',rx_max_pending))
            ringInfo.append(('rx_mini_max_pending',rx_mini_max_pending))
            ringInfo.append(('rx_jumbo_max_pending',rx_jumbo_max_pending))
            ringInfo.append(('tx_max_pending',tx_max_pending))
            ringInfo.append(('rx_pending',rx_pending))
            ringInfo.append(('rx_mini_pending',rx_mini_pending))
            ringInfo.append(('rx_jumbo_pending',rx_jumbo_pending))
            ringInfo.append(('tx_pending',tx_pending))

        except:
            ringInfo.append(("not supported","not supported")) 
        
        return ringInfo

    def getPauseParameters(self):
        pauseInfo=[]
        pauseInfo.append("--- pause parameters ---") 
        try:
            ethtool_pauseparam_struct = array.array('B', struct.pack('IIII',0x00000012,0,0,0))
            self._send_ioctl(ethtool_pauseparam_struct)
            cmd,autoneg,rx_pause,tx_pause = struct.unpack("IIII",ethtool_pauseparam_struct)            

            pauseInfo.append(('autoneg',autoneg))
            pauseInfo.append(('rx_pause',rx_pause))
            pauseInfo.append(('tx_pause',tx_pause))

        except Exception as Ex:
            #pprint(Ex)
            pauseInfo.append(("not supported","not supported")) 
        
        return pauseInfo

    def getFeatures(self):
        strings = list(self.get_StringSet(4)) # ETH_SS_FEATURES
        n_stats = len(strings)
        n_chunks = int(n_stats/32)

        retData=["--- Features ---"]

        ethtool_get_features_block_struct = array.array('B', struct.pack('IIII',0,0,0,0))
        available,requested,active,never_changed = struct.unpack("IIII",ethtool_get_features_block_struct)

        ethtool_gfeatures_struct=array.array('B', struct.pack("II",0x0000003a,n_stats)) #ETHTOOL_GFEATURES	
        # add new ethtool_get_features_block_struct for every stat
        ethtool_gfeatures_struct.extend(bytearray(struct.pack('IIII',0,0,0,0) * n_chunks)) # 32 stats at a time
        self._send_ioctl(ethtool_gfeatures_struct)
        
        FEATURE_LEN=16
        for index in range(0,n_chunks):
            offset = 8 + FEATURE_LEN * index
            ethtool_get_features_block_struct = ethtool_gfeatures_struct[offset:offset+FEATURE_LEN]
            availableMask,requestedMask,activeMask,never_changedMask = struct.unpack("IIII",ethtool_get_features_block_struct)
            
            mask=1
            for statIndex in range(index,index+32):
                if (availableMask & mask) > 0:
                    availableFlag = 'on'
                else:
                    availableFlag = 'off'
                    
                if (requestedMask & mask) > 0:
                    requestedFlag = 'on'
                else:
                    requestedFlag = 'off'      
                    
                if (activeMask & mask) > 0:
                    activeFlag = 'on'
                else:
                    activeFlag = 'off'      
                    
                neverChangedFlag = (never_changedMask & mask) > 0
                    
                statStr = strings[statIndex]
                if len(statStr) > 0:
                    dString = activeFlag
                    if neverChangedFlag:
                        dString += " [fixed]"

                    retData.append((statStr,dString))
                mask=mask<<1

            return retData
        
def prettyTheData(srcList):
    for index,entry in enumerate(srcList):
        try:
            name,dList = entry
            while len(name) < 30: name +="."
            srcList[index]=(name,dList)
        except: #is the 'title' of the group
            pass
        

if __name__ == '__main__':
    import sys
    if sys.version_info[0] != 3:
        print("This script requires Python version 3")
#        sys.exit(1)    
        
    ifname = sys.argv[1]
    et = PortDumper(ifname)
    info=[]
    try:
        info = et.getDriverInfo()
    except:
        print("Unable to gather information for device: {}".format(ifname))
        sys.exit(1)    

    info.extend(et.getCoalesceInfo())
    info.extend(et.getLinkInfo())
    info.extend(et.getEneryEfficientEthernetInfo())
    info.extend(et.getRingParameters())
    info.extend(et.getPauseParameters())
    info.extend(et.getFeatures())
    info.append("--- Ethtool Values ---")
    info.extend(et.getEthtoolValue(0x0000000a,"Link State"))
    info.extend(et.getEthtoolValue(0x00000014,"RX Checksum Enabled"))
    info.extend(et.getEthtoolValue(0x00000016,"TX Checksum Enabled"))
    info.extend(et.getEthtoolValue(0x00000018,"Scatter/Gather Enabled"))
    info.extend(et.getEthtoolValue(0x0000001e,"TSO Enabled"))
    info.extend(et.getEthtoolValue(0x00000020,"permanent hardware address"))
    info.extend(et.getEthtoolValue(0x00000021,"UFO Enabled"))
    info.extend(et.getEthtoolValue(0x00000023,"GSO Enabled"))
    
    flagsList =et.getEthtoolValue(0x00000025,"Flags Bitmap")
    #show this as HEX data, as it is a bitmap
    name,data = flagsList[0]
    data = "0x{:08x}".format(data)
    info.extend([(name,data)])
    info.extend(et.getEthtoolValue(0x0000002b,"GRO Enabled"))

    info.extend(et.getEthtoolValue(0x0000002d,"RX rings available for LB"))    
    info.extend(et.getEthtoolValue(0x0000002e,"RX class rule count"))
    info.extend(et.getEthtoolValue(0x0000002f,"RX classification rule"))
    info.extend(et.getEthtoolValue(0x00000030,"All RX classification rule"))

    info.extend(et.get_stats())
    
    print("PortDumper " + verStr + ". Port: " + ifname)
    
    prettyTheData(info)

    for entry in info:
        try:
            name,value = entry
            print("\t{}\t: {}".format(name,value))
        except: #is the 'title' of the group
            print("\n" + entry)
        

