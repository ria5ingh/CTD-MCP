from typing import Any, Dict, Optional, List
from mcp.server.fastmcp import FastMCP
from src.client import CTDClient


class ProtocolsModule:
    def __init__(self, client: CTDClient):
        self.client = client
        # Defining the baseline mapping according to the wizard script logic
        self.default_protocols = {
            "honeywell.Firewall": True, "cclink_ie.cclink_ie_field": True, "fortinet_discovery": True,
            "toshiba_tcnet": True, "terasaki.layer_2_broadcast": True, "rapienet": False, "rpc": True,
            "dns": True, "ssh": True, "dhcp": True, "ftp": True, "ftp_data": True, "http": True,
            "icmp": True, "igmp": True, "modbus.tcp": True, "browser": True, "arp": True, "cip": True,
            "enip": True, "s7comm": True, "profinet.dcp": True, "llc": True, "lldp": True, "dcerpc": True,
            "mms": True, "tftp": True, "profinet.pn_io": True, "ntp": True, "opc_ua": True, "nbdgm": True,
            "ntlmssp": True, "samr": True, "vnc": True, "ssl": True, "s7commplus": True, "cotp": True,
            "smb": True, "smb_pipe": True, "lanman": True, "atsvc": True, "srvsvc": True, "rdp": True,
            "ge_srtp": True, "goose": True, "egd": True, "roc_plus": True, "bnc": True, "ge_sdi": True,
            "ge_sdiclassic": True, "ge_quickpanel": True, "foxboro": True, "ff": False, "honeywell.FtebCipMsg": False,
            "honeywell.PsCdaCeeNtComm": False, "ldap": False, "kerberos": False, "rlogin": False, "smtp": False,
            "pop": False, "imap": False, "honeywell.PsCdaCeeNtPeer": False, "hart_ip": False, "telnet": False,
            "totalflow": False, "bacnet": False, "ovation": False, "fwl_load": False, "symphony_plus": False,
            "pinet.pi1": False, "pinet.pi3": True, "iec104": False, "rcdp": True, "eterra": False,
            "eterra_workstation": False, "abb_dms": False, "red_lion": True, "synchrophasor": True, "mqtt": True,
            "citect": True, "keyence.keyence_kv_studio": True, "profinet.rt": True, "beckhoff": True, "tpkt": True,
            "portmapper": True, "hsrp": True, "cpha": True, "rtcp": True, "ge_enervista": False, "epm": True,
            "sel": True, "sip": True, "skinny": True, "radius": True, "capwap_control": True, "capwap_data": True,
            "wlan": True, "hp_switch": True, "ptp": True, "abb_melody": True, "factorytalk_rna": True,
            "valmet_dna.damatic_configuration": True, "sampled_values": True, "cspv4": True, "hirschmann": True,
            "digi_real_port": True, "ethercat": True, "mdns": True, "llmnr": True, "icmpv6": True, "nbns": True,
            "h1": True, "bittorrent": True, "fins.tcp": True, "melsec": True, "ovation.ovationrpc": True,
            "red_lion.red_lion_discovery": True, "tridium_fox": True, "sattbus": True, "vnet.odeq": True,
            "vnet": True, "vnet.vhf": True, "ovation.alarm": True, "modbus.serial": True, "proconos": True,
            "tsaa": True, "tristation": True, "axe": True, "deltav.device_connection": True, "deltav.RtProgLog": True,
            "deltav.FlashDownload": True, "omniflow": True, "dnp3": True, "egd_cmp": True, "p2": False,
            "ovation.dbxmit": False, "ovation.ptedit": False, "honeywell.comm_setup": False, "honeywell.EpicMo": False,
            "opto": False, "opto_mmp": False, "lantronix": False, "cti": False, "bailey.tcp": False,
            "bailey.serial": False, "ge_alm": True, "prosoft_discovery": True, "iec101": False,
            "bailey.infininet": False, "secsgem": False, "dacp": False, "iec103": False, "keyence.keyence_log_reporter": True,
            "cognex_discovery": True, "kongsberg": True, "portwell": True, "ovation.admd": False, "mndp": True,
            "siprotec": True, "keyence.keyencehostlink": False, "foxboro_rtv": True, "knapp": True, "linux_ha": True,
            "comtrol_ns_link": True, "slmp": True, "melsoft": True, "wonderware.iotalk": True, "altus.alnet": True,
            "alspa": True, "schneider_netmanage": True, "bnr.ina2000": True, "mdlc.mdlc_management": True,
            "mdlc.mdlc_data": True, "caterpillar.gw_to_vims": False, "caterpillar.hmi_to_gw": False, "wsd": True,
            "abb_dcs.rnrp": True, "cygnet": False, "enhanced_modbus": True, "java.jrmi": True, "java.java_rpc": True,
            "t3000.automation_server_data": True, "t3000.gw_discover": True, "nmea_0183": True, "opto_softpac_agent": False,
            "honeywell.safety_manager": True, "honeywell.dsa_discovery": True, "iq3": True, "valmet_dna.valmet_dna_data": True,
            "valmet_dna.valmet_dna_frontend": False, "valmet_dna.valmet_dna_alarms": True, "wudo": True, "sentinel_srm": True,
            "valmet_dna.damatic_data": True, "bsap": True, "clear_scada": True, "matrikon_opc": True, "sbus": True,
            "moxa_udp": True, "schneider_ion": True, "ethernet_powerlink": True, "trdp.trdp_pd": True, "koyo": True,
            "xpact.xpact_data": True, "xpact.xpact_discovery": True, "xpact.xpact_diagnostics": True, "cola_a": True,
            "zabbix.zabbix_agent": True, "zabbix.zabbix_sender": True, "sinaut_fw8": False, "ttsac": True,
            "ge_ifix": True, "wago": True, "siemens_iem": True, "max_dna": False, "codesysv3": True, "xg5000": True,
            "flnet": True, "pf_dcp": True, "gaz_modem": True, "codesysv2": True, "dlms_cosem": True, "b32": False,
            "snmp": True, "pcwin": False, "tds": True, "mitsubishi_got": True, "jrc_vessel_display": True, "focas": True,
            "gcode": False, "exi3000.discovery": False, "exi3000.mgmt": False, "meggitt.vibrometer": True,
            "abb_netconfig": True, "fins.udp": True, "terasaki.negotiation": True, "terasaki.realtime_data_sync": False,
            "siemens_cargo.cargo_compact": True, "siemens_cargo.cargo_compact_sensor": False,
            "siemens_cargo.cargo_compact_control": False, "smiths_detection.broadcast": True, "mdlc.mdlc_proprietary": False,
            "telvent.oasys": False
        }

    def register_tools(self, mcp: FastMCP):

        @mcp.tool()
        def get_dpi_protocols(
            site_id: str = "1",
            status_filter: Optional[bool] = None,
            summary_only: bool = False
        ) -> Dict[str, Any]:
            """
            Retrieve Deep Packet Inspection (DPI) protocol configurations from CTD.
            
            Args:
                site_id: CTD site ID identifier (default "1").
                status_filter: Filter to return only protocols that are enabled (True) or disabled (False).
                summary_only: If True, returns only total counts of protocols to save tokens.
            """
            try:
                proto_data = self.client.request("GET", "/ranger/ranger_api/protocols", params={"site_id": site_id})
                
                if not proto_data.get("success"):
                    return {"status": "ERROR", "error": "Failed to retrieve protocol data."}

                protocols_list = proto_data.get("data", [])
                
                enabled_count = 0
                disabled_count = 0
                formatted_protocols = []

                for proto in protocols_list:
                    name = proto.get("name", "Unknown")
                    is_enabled = proto.get("is_enabled")
                    
                    if is_enabled:
                        enabled_count += 1
                    else:
                        disabled_count += 1
                        
                    if status_filter is not None and is_enabled != status_filter:
                        continue
                        
                    if not summary_only:
                        formatted_protocols.append({
                            "name": name,
                            "enabled": is_enabled
                        })

                res = {
                    "status": "PASS",
                    "total_protocols": len(protocols_list),
                    "enabled_count": enabled_count,
                    "disabled_count": disabled_count
                }

                if not summary_only:
                    res["protocols"] = formatted_protocols

                return res

            except Exception as e:
                return {"status": "ERROR", "error": f"Failed to retrieve DPI protocols: {str(e)}"}

        @mcp.tool()
        def audit_protocol_drift(
            site_id: str = "1"
        ) -> Dict[str, Any]:
            """
            Compare live DPI protocol configurations against the federal Golden Baseline to identify drift.
            
            Args:
                site_id: CTD site ID identifier (default "1").
            """
            try:
                proto_data = self.client.request("GET", "/ranger/ranger_api/protocols", params={"site_id": site_id})
                
                if not proto_data.get("success"):
                    return {"status": "ERROR", "error": "Failed to retrieve protocol data."}

                protocols_list = proto_data.get("data", [])
                drifted_protocols = []
                
                for proto in protocols_list:
                    name = proto.get("name", "Unknown")
                    is_enabled = proto.get("is_enabled")
                    
                    if name in self.default_protocols:
                        expected_status = self.default_protocols[name]
                        if is_enabled != expected_status:
                            drifted_protocols.append({
                                "protocol": name,
                                "live_status": is_enabled,
                                "baseline_expected": expected_status
                            })

                status = "PASS"
                if drifted_protocols:
                    status = "REVIEW"

                return {
                    "status": status,
                    "drift_detected": len(drifted_protocols) > 0,
                    "drift_count": len(drifted_protocols),
                    "drifted_protocols": drifted_protocols if drifted_protocols else "No deviations found. System matches baseline."
                }

            except Exception as e:
                return {"status": "ERROR", "error": f"Failed to audit protocol drift: {str(e)}"}

    def register_resources(self, mcp: FastMCP):
        pass