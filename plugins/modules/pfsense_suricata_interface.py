#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Orion Poplawski <orion@nwra.com>
# Copyright: (c) 2019, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: pfsense_suricata_interface
short_description: Manage pfSense suricata interfaces
description:
  - Manage pfSense suricata interfaces. This requires the pfSense suricata package to be installed.
version_added: 0.1.0
author: Orion Poplawski (@opoplawski)
options:
  interface:
    description: Interface of the suricata instance. In most cases, you will want to choose lan here if this is the first Suricata configured interface.
    required: true
    type: str
  descr:
    description: The description of the suricata interface.
    required: true
    type: str
  state:
    description: State in which to leave the suricata interface.
    choices: [ "present", "absent" ]
    default: present
    type: str
  enable:
    description: Enable Suricata inspection on the interface. Defaults to true.
    type: bool
  alertsystemlog:
    description: >
      Suricata will send Alerts from this interface to the firewall's system log. NOTE: the FreeBSD syslog daemon will automatically truncate exported messages
      to 480 bytes max. Defaults to false.
    type: bool
    version_added: 0.2.0
  alertsystemlog_facility:
    description: Syslog facility of the suricata interface. Defaults to local1.
    choices: ['auth', 'authpriv', 'daemon', 'kern', 'security', 'syslog', 'user', 'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7'
    ]
    type: str
    version_added: 0.2.0
  alertsystemlog_priority:
    description: Syslog priority of the suricata interface. Defaults to notice.
    choices: ['emergency', 'critical', 'alert', 'error', 'warning', 'notice', 'info', 'debug']
    type: str
    version_added: 0.2.0
  enable_stats_collection:
    description: Suricata will periodically gather performance statistics for this interface. Default is false.
    type: bool
    version_added: 0.2.0
  stats_upd_interval:
    description: The update interval in seconds for collection of performance statistics. Defaults to 10.
    type: int
    version_added: 0.2.0
  enable_stats_log:
    description: Suricata will periodically log statistics for this interface to a CSV text log file. Default is false.
    type: bool
    version_added: 0.2.0
  append_stats_log:
    description: Suricata will append-to instead of clearing the stats log file when restarting. Default is false.
    type: bool
    version_added: 0.2.0
  enable_telegraf_stats:
    description: Suricata will periodically log statistics for this interface to Telegraf via a Unix socket. Default is false.
    type: bool
    version_added: 0.2.0
  enable_http_log:
    description: Suricata will log decoded HTTP traffic for the interface. Default is true.
    type: bool
    version_added: 0.2.0
  append_http_log:
    description: Suricata will append-to instead of clearing HTTP log file when restarting. Default is true.
    type: bool
    version_added: 0.2.0
  http_log_extended:
    description: Suricata will log extended HTTP information. Default is true.
    type: bool
    version_added: 0.2.0
  enable_tls_log:
    description: Suricata will log TLS handshake traffic for the interface. Default is false.
    type: bool
    version_added: 0.2.0
  enable_tls_store:
    description: Suricata will log and store TLS certificates for the interface. Default is false.
    type: bool
    version_added: 0.2.0
  tls_log_extended:
    description: Suricata will log extended TLS info such as fingerprint. Default is true.
    type: bool
    version_added: 0.2.0
  enable_file_store:
    description: >
      Suricata will extract and store files from application layer streams. Default is false. WARNING: Enabling file-store will consume a significant amount of
      disk space on a busy network!
    type: bool
    version_added: 0.2.0
  file_store_logdir:
    description: >
      File Store Logging Directory of the suricata interface. Enter directory path for saving the files extracted from application layer streams. When blank,
      the default path is a "filestore" sub-directory under the interface logging sub-directory in /var/log/suricata/.
    type: str
    version_added: 0.2.0
  enable_pcap_log:
    description: >
      Suricata will log decoded packets for the interface in pcap-format. Default is false. This can consume a significant amount of disk space when enabled.
      Use the Packet Log Conditional setting to select packets for capture.
    type: bool
    version_added: 0.2.0
  max_pcap_log_size:
    description: >
      Maximum size in MB for a packet log file. When the packet log file size reaches the set limit, it will be rotated and a new one created. Defaults to 32.
    type: str
    version_added: 0.2.0
  max_pcap_log_files:
    description: >
      Maximum number of packet log files to maintain. When the number of packet log files reaches the set limit, the oldest file will be overwritten.
      Defaults to 1000.
    type: str
    version_added: 0.2.0
  enable_verbose_logging:
    description: Suricata will log additional information to the suricata.log file when starting up and shutting down. Default is false.
    type: bool
    version_added: 0.2.0
  enable_eve_log:
    description: Suricata will output selected info in JSON format to a single file or to syslog. Default is false.
    type: bool
    version_added: 0.2.0
  eve_output_type:
    description: >
      EVE Output Type of the suricata interface. Choosing `regular` is suggested and is the default value. `redis` is used for output to a Redis server, and
      the unix_* options output to a user-created socket.
    choices: ['regular', 'syslog', 'redis', 'unix_dgram', 'unix_stream']
    type: str
    version_added: 0.2.0
  eve_systemlog_facility:
    description: EVE Syslog Output Facility of the suricata interface. Defaults to local1.
    choices: ['auth', 'authpriv', 'daemon', 'kern', 'security', 'syslog', 'user', 'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7'
    ]
    type: str
    version_added: 0.2.0
  eve_systemlog_priority:
    description: EVE Syslog Output Priority of the suricata interface. Defaults to info.
    choices: ['emerg', 'crit', 'alert', 'err', 'warning', 'notice', 'info']
    type: str
    version_added: 0.2.0
  eve_redis_server:
    description: The EVE Redis server to log to. Defaults to 127.0.0.1.
    type: str
    version_added: 0.2.0
  eve_redis_port:
    description: The EVE Redis port to log to. Defaults to 6379.
    type: str
    version_added: 0.2.0
  eve_redis_mode:
    description: EVE REDIS Mode of the suricata interface. Defaults to list.
    choices: ['list', 'rpush', 'channel']
    type: str
    version_added: 0.2.0
  eve_redis_key:
    description: EVE REDIS Key. Defaults to suricata.
    type: str
    version_added: 0.2.0
  eve_log_alerts_xff:
    description: Log X-Forwarded-For IP addresses.  Default is false.
    type: bool
    version_added: 0.2.0
  eve_log_alerts_xff_mode:
    description: >
      EVE X-Forwarded-For operational mode. `extra-data` adds an extra field while `overwrite` overwrites the existing source or destination IP.
      Defaults to extra-data.
    choices: ['extra-data', 'overwrite']
    type: str
    version_added: 0.2.0
  eve_log_alerts_xff_deployment:
    description: EVE X-Forwarded-For deployment.  `reverse` deployment uses the last IP address while `forward` uses the first one. Defaults to reverse.
    choices: ['reverse', 'forward']
    type: str
    version_added: 0.2.0
  eve_log_alerts_xff_header:
    description: >
      EVE Log Alert X-Forwarded-For header where actual IP address is reported. If more than one IP address is present, the last one will be used.
      Defaults to X-Forwarded-For.
    type: str
    version_added: 0.2.0
  eve_log_alerts:
    description: Suricata will output alerts via EVE.
    type: bool
    version_added: 0.2.0
  eve_log_alerts_payload:
    description: >
      EVE Log the payload data with alerts.  Options are `off`(disable payload logging), `only-printable` (lossy) format, `only-base64` encoded or `on`.
      See Suricata documentation. Defaults to on.
    choices: ['off', 'only-base64', 'only-printable', 'on']
    type: str
    version_added: 0.2.0
  eve_log_alerts_packet:
    description: Log a packet dump with alerts.
    type: bool
    version_added: 0.2.0
  eve_log_alerts_http:
    description: Log additional HTTP data.
    type: bool
    version_added: 0.2.0
  eve_log_alerts_metadata:
    description: Include App Layer metadata.
    type: bool
    version_added: 0.2.0
  eve_log_anomaly:
    description: >
        Suricata will log packet anomalies such as truncated packets, packets with invalid IP/UDP/TCP length values and other events that render the packet
        invalid for further processing. Networks with high rates of anomalies may experience packet processing degradation.EVE Log Anomalies of the suricata
        interface.
    type: bool
    version_added: 0.2.0
  eve_log_anomaly_type_decode:
    description: Log packet decode anomaly events.
    type: bool
    version_added: 0.2.0
  eve_log_anomaly_type_stream:
    description: Log packet stream anomaly events.
    type: bool
    version_added: 0.2.0
  eve_log_anomaly_type_applayer:
    description: Log packet applayer anomaly events.
    type: bool
    version_added: 0.2.0
  eve_log_anomaly_packethdr:
    description: Log packet header for anomaly events.
    type: bool
    version_added: 0.2.0
  eve_log_dns:
    description: Log DNS.
    type: bool
    version_added: 0.2.0
  eve_log_ftp:
    description: Log FTP.
    type: bool
    version_added: 0.2.0
  eve_log_http:
    description: Log HTTP.
    type: bool
    version_added: 0.2.0
  eve_log_http2:
    description: Log HTTP2.
    type: bool
    version_added: 0.2.0
  eve_log_ikev2:
    description: Log IKE.
    type: bool
    version_added: 0.2.0
  eve_log_krb5:
    description: Log Kerberos.
    type: bool
    version_added: 0.2.0
  eve_log_nfs:
    description: Log NFS.
    type: bool
    version_added: 0.2.0
  eve_log_rdp:
    description: Log RDP.
    type: bool
    version_added: 0.2.0
  eve_log_rfb:
    description: Log RFB.
    type: bool
    version_added: 0.2.0
  eve_log_sip:
    description: Log SIP.
    type: bool
    version_added: 0.2.0
  eve_log_smb:
    description: Log SMB.
    type: bool
    version_added: 0.2.0
  eve_log_smtp:
    description: Log SMTP.
    type: bool
    version_added: 0.2.0
  eve_log_tftp:
    description: Log TFTP.
    type: bool
    version_added: 0.2.0
  eve_log_dhcp:
    description: Log DHCP Messages.
    type: bool
    version_added: 0.2.0
  eve_log_drop:
    description: Log Dropped Traffic.
    type: bool
    version_added: 0.2.0
  eve_log_flow:
    description: Log Flows.
    type: bool
    version_added: 0.2.0
  eve_log_mqtt:
    description: Log MQTT.
    type: bool
    version_added: 0.2.0
  eve_log_netflow:
    description: Log Net Flows.
    type: bool
    version_added: 0.2.0
  eve_log_stats:
    description: Log Perf Stats.
    type: bool
    version_added: 0.2.0
  eve_log_snmp:
    description: Log SNMP.
    type: bool
    version_added: 0.2.0
  eve_log_ssh:
    description: Log SSH Handshakes.
    type: bool
    version_added: 0.2.0
  eve_log_tls:
    description: Log TLS Handshakes.
    type: bool
    version_added: 0.2.0
  eve_log_files:
    description: Log Tracked Files.
    type: bool
    version_added: 0.2.0
  eve_log_http_extended:
    description: Log Extended HTTP Info.
    type: bool
    version_added: 0.2.0
  eve_log_tls_extended:
    description: Log Extended TLS Info.
    type: bool
    version_added: 0.2.0
  eve_log_dhcp_extended:
    description: Log Extended DHCP Info.
    type: bool
    version_added: 0.2.0
  eve_log_smtp_extended:
    description: Log Extended SMTP Info.
    type: bool
    version_added: 0.2.0
  eve_log_http_extended_headers:
    description: >
      Extended HTTP headers for logging. Defaults to ['accept', 'accept-charset', 'accept-datetime', 'accept-encoding', 'accept-language', 'accept-range',
      'age', 'allow', 'authorization', 'cache-control', 'connection', 'content-encoding', 'content-language', 'content-length', 'content-location',
      'content-md5', 'content-range', 'content-type', 'cookie', 'date', 'dnt', 'etags', 'from', 'last-modified', 'link', 'location', 'max-forwards', 'origin',
      'pragma', 'proxy-authenticate', 'proxy-authorization', 'range', 'referrer', 'refresh', 'retry-after', 'server', 'set-cookie', 'te', 'trailer',
      'transfer-encoding', 'upgrade', 'vary', 'via', 'warning', 'www-authenticate', 'x-authenticated-user', 'x-flash-version', 'x-forwarded-proto',
      'x-requested-with'].
    type: list
    elements: str
    version_added: 0.2.0
  eve_log_smtp_extended_fields:
    description: Extended SMTP fields for logging. Defaults to ['bcc', 'received', 'reply-to', 'x-mailer', 'x-originating-ip'].
    type: list
    elements: str
    version_added: 0.2.0
  eve_log_tls_extended_fields:
    description: Extended TLS extended fields for logging. Defaults to [].
    type: list
    elements: str
    version_added: 0.2.0
  eve_log_files_magic:
    description: Suricata will force logging magic on all logged Tracked Files. Default is false.
    type: bool
    version_added: 0.2.0
  eve_log_files_hash:
    description: Suricata will generate checksums for all logged Tracked Files using the chosen algorithm. Default is `none`.
    choices: ['none', 'md5', 'sha1', 'sha256']
    type: str
    version_added: 0.2.0
  eve_log_stats_totals:
    description: Log totals.
    type: bool
    version_added: 0.2.0
  eve_log_stats_deltas:
    description: Log deltas.
    type: bool
    version_added: 0.2.0
  eve_log_stats_threads:
    description: Log per thread.
    type: bool
    version_added: 0.2.0
  blockoffenders:
    description: Automatically block hosts that generate a Suricata alert.
    type: bool
    version_added: 0.2.0
  ips_mode:
    description: >
      IPS blocking mode operation. `ips_legacy_mode` inspects copies of packets while `ips_inline_mode` inserts the Suricata inspection engine into the network
      stack between the NIC and the OS. Defaults to `ips_mode_legacy`.
    choices: ['ips_mode_legacy', 'ips_mode_inline']
    type: str
    version_added: 0.2.0
  ips_netmap_threads:
    description: >
      The number of netmap threads to use. When set to "auto", Suricata will query the system for the number of supported netmap queues,  and it will use a
      matching number of netmap theads. The NIC hosting this interface registered 2 queue(s) with the kernel. Defaults to auto.
    type: str
    version_added: 0.2.0
  blockoffenderskill:
    description: Kill firewall states for the blocked IP.  Default is true.
    type: bool
    version_added: 0.2.0
  blockoffendersip:
    description: Which IP extracted from the packet you wish to block. Choosing `both` is suggested, and it is the default value.
    choices: ['src', 'dst', 'both']
    type: str
    version_added: 0.2.0
  block_drops_only:
    description: >
      Insert blocks only when rule signatures having the DROP action are triggered.  When false, any rule action (ALERT or DROP) will generate a block of the
      offending host.  Default is false.
    type: bool
    version_added: 0.2.0
  passlistname:
    description: The pass list name. Defaults to default.
    choices: ['default', 'none']
    type: str
    version_added: 0.2.0
  runmode:
    description: >
      Suricata run mode setting. Default is `autofp` and is the recommended setting for IDS-only and Legacy Blocking Mode. `workers` uses multiple worker
      threads, each of which processes the packets it acquires through all the decode and detect modules. `workers` runmode is preferred for Inline IPS Mode
      blocking because it offers superior performance in that configuration. `single` uses only a single thread for all operations, and is intended for use
      only in testing or development instances. Defaults to autofp.
    choices: ['autofp', 'workers', 'single']
    type: str
    version_added: 0.2.0
  autofp_scheduler:
    description: >
      The kind of flow load balancer used by the flow pinned autofp mode.  `hash` assigns the flow to a thread using the 5-7 tuple hash. `ippair` assigns the
      flow to a thread using addresses only. This setting is applicable only when the Run Mode is set to "autofp". Defaults to hash.
    choices: ['hash', 'ippair']
    type: str
    version_added: 0.2.0
  max_pending_packets:
    description: Number of simultaneous packets to process. Defaults to 1024.
    type: int
    version_added: 0.2.0
  detect_eng_profile:
    description: Detection engine profile. Defaults to medium.
    choices: ['low', 'medium', 'high']
    type: str
    version_added: 0.2.0
  mpm_algo:
    description: >
      Multi-Pattern Matcher (MPM) algorithm. `auto` is the default, and is the best choice for almost all systems. `auto` will use hyperscan if available.
    choices: ['auto', 'ac', 'ac-bs', 'ac-ks', 'hs']
    type: str
    version_added: 0.2.0
  sgh_mpm_context:
    description: Signature Group Header multi-pattern matcher context. Defaults to auto.
    choices: ['auto', 'full', 'single']
    type: str
    version_added: 0.2.0
  inspect_recursion_limit:
    description: Limit for recursive calls in content inspection code. Defaults to 3000.
    type: int
    version_added: 0.2.0
  delayed_detect:
    description: Suricata will build list of signatures after packet capture threads have started. Default is false.
    type: bool
    version_added: 0.2.0
  intf_promisc_mode:
    description: Suricata will place the monitored interface in promiscuous mode when checked. Default is true.
    type: bool
    version_added: 0.2.0
  intf_snaplen:
    description: Vvalue in bytes for the interface PCAP snaplen. This parameter is only valid when IDS or Legacy Mode IPS is enabled. Defaults to 1518.
    type: int
    version_added: 0.2.0
  homelistname:
    description: The Home Net you want this interface to use. Defaults to default.
    choices: ['default']
    type: str
    version_added: 0.2.0
  externallistname:
    description: The External Net you want this interface to use. Defaults to default.
    choices: ['default']
    type: str
    version_added: 0.2.0
  suppresslistname:
    description: The suppression or filtering file you want this interface to use. Default option disables suppression and filtering. Defaults to default.
    type: str
    version_added: 0.2.0
  flow_udp_emerg_established_timeout:
    description: The flow udp emerg established timeout.
    type: str
    version_added: 0.2.0
  flow_memcap:
    description: The flow_memcap.
    type: str
    version_added: 0.2.0
  ssh_parser:
    description: The ssh_parser.
    type: str
    version_added: 0.2.0
  ips_policy_enable:
    description: The ips_policy_enable.
    type: str
    version_added: 0.2.0
  imap_parser:
    description: The imap_parser.
    type: str
    version_added: 0.2.0
  pgsql_parser:
    description: The pgsql_parser.
    type: str
    version_added: 0.2.0
  tls_parser:
    description: The tls_parser.
    type: str
    version_added: 0.2.0
  smtp_parser_decode_quoted_printable:
    description: The smtp_parser_decode_quoted_printable.
    type: str
    version_added: 0.2.0
  smtp_parser:
    description: The smtp_parser.
    type: str
    version_added: 0.2.0
  host_prealloc:
    description: The host_prealloc.
    type: str
    version_added: 0.2.0
  quic_parser:
    description: The quic_parser.
    type: str
    version_added: 0.2.0
  http2_parser:
    description: The http2_parser.
    type: str
    version_added: 0.2.0
  ip_frag_timeout:
    description: The ip_frag_timeout.
    type: str
    version_added: 0.2.0
  reassembly_to_client_chunk:
    description: The reassembly_to_client_chunk.
    type: str
    version_added: 0.2.0
  smtp_parser_compute_body_md5:
    description: The smtp_parser_compute_body_md5.
    type: str
    version_added: 0.2.0
  stream_memcap:
    description: The stream_memcap.
    type: str
    version_added: 0.2.0
  autoflowbitrules:
    description: The autoflowbitrules.
    type: str
    version_added: 0.2.0
  ip_max_frags:
    description: The ip_max_frags.
    type: str
    version_added: 0.2.0
  stream_prealloc_sessions:
    description: The stream_prealloc_sessions.
    type: str
    version_added: 0.2.0
  dns_request_flood_limit:
    description: The dns_request_flood_limit.
    type: str
    version_added: 0.2.0
  smb_parser:
    description: The smb_parser.
    type: str
    version_added: 0.2.0
  rulesets:
    description: The rulesets.
    type: list
    elements: str
    version_added: 0.2.0
  defrag_memcap_policy:
    description: The defrag_memcap_policy.
    type: str
    version_added: 0.2.0
  tls_encrypt_handling:
    description: The tls_encrypt_handling.
    type: str
    version_added: 0.2.0
  flow_tcp_emerg_closed_timeout:
    description: The flow_tcp_emerg_closed_timeout.
    type: str
    version_added: 0.2.0
  flow_memcap_policy:
    description: The flow_memcap_policy.
    type: str
    version_added: 0.2.0
  frag_hash_size:
    description: The frag_hash_size.
    type: str
    version_added: 0.2.0
  telnet_parser:
    description: The telnet_parser.
    type: str
    version_added: 0.2.0
  stream_checksum_validation:
    description: The stream_checksum_validation.
    type: str
    version_added: 0.2.0
  reassembly_memcap:
    description: The reassembly_memcap.
    type: str
    version_added: 0.2.0
  ntp_parser:
    description: The ntp_parser.
    type: str
    version_added: 0.2.0
  enable_dns_log:
    description: The enable_dns_log.
    type: str
    version_added: 0.2.0
  flow_prune:
    description: The flow_prune.
    type: str
    version_added: 0.2.0
  max_synack_queued:
    description: The max_synack_queued.
    type: str
    version_added: 0.2.0
  host_os_policy:
    description: The host_os_policy.
    type: str
    version_added: 0.2.0
  flow_tcp_established_timeout:
    description: The flow_tcp_established_timeout.
    type: str
    version_added: 0.2.0
  append_dns_log:
    description: The append_dns_log.
    type: str
    version_added: 0.2.0
  dns_state_memcap:
    description: The dns_state_memcap.
    type: str
    version_added: 0.2.0
  host_memcap:
    description: The host_memcap.
    type: str
    version_added: 0.2.0
  host_hash_size:
    description: The host_hash_size.
    type: str
    version_added: 0.2.0
  flow_udp_new_timeout:
    description: The flow_udp_new_timeout.
    type: str
    version_added: 0.2.0
  ftp_parser:
    description: The ftp_parser.
    type: str
    version_added: 0.2.0
  dhcp_parser:
    description: The dhcp_parser.
    type: str
    version_added: 0.2.0
  rfb_parser:
    description: The rfb_parser.
    type: str
    version_added: 0.2.0
  app_layer_error_policy:
    description: The app_layer_error_policy.
    type: str
    version_added: 0.2.0
  dcerpc_parser:
    description: The dcerpc_parser.
    type: str
    version_added: 0.2.0
  enable_tracked_files_md5:
    description: The enable_tracked_files_md5.
    type: str
    version_added: 0.2.0
  enip_parser:
    description: The enip_parser.
    type: str
    version_added: 0.2.0
  rule_sid_off:
    description: The rule_sid_off.
    type: list
    elements: str
    version_added: 0.2.0
  flow_hash_size:
    description: The flow_hash_size.
    type: str
    version_added: 0.2.0
  ikev2_parser:
    description: The ikev2_parser.
    type: str
    version_added: 0.2.0
  enable_midstream_sessions:
    description: The enable_midstream_sessions.
    type: str
    version_added: 0.2.0
  flow_tcp_emerg_established_timeout:
    description: The flow_tcp_emerg_established_timeout.
    type: str
    version_added: 0.2.0
  flow_udp_established_timeout:
    description: The flow_udp_established_timeout.
    type: str
    version_added: 0.2.0
  flow_emerg_recovery:
    description: The flow_emerg_recovery.
    type: str
    version_added: 0.2.0
  flow_tcp_emerg_new_timeout:
    description: The flow_tcp_emerg_new_timeout.
    type: str
    version_added: 0.2.0
  flow_icmp_established_timeout:
    description: The flow_icmp_established_timeout.
    type: str
    version_added: 0.2.0
  http_parser:
    description: The http_parser.
    type: str
    version_added: 0.2.0
  msn_parser:
    description: The msn_parser.
    type: str
    version_added: 0.2.0
  frag_memcap:
    description: The frag_memcap.
    type: str
    version_added: 0.2.0
  flow_udp_emerg_new_timeout:
    description: The flow_udp_emerg_new_timeout.
    type: str
    version_added: 0.2.0
  stream_drop_invalid:
    description: The stream_drop_invalid.
    type: str
    version_added: 0.2.0
  enable_iprep:
    description: The enable_iprep.
    type: str
    version_added: 0.2.0
  libhtp_policy:
    description: The libhtp_policy.
    type: str
    version_added: 0.2.0
  midstream_policy:
    description: The midstream_policy.
    type: str
    version_added: 0.2.0
  dns_global_memcap:
    description: The dns_global_memcap.
    type: str
    version_added: 0.2.0
  flow_tcp_closed_timeout:
    description: The flow_tcp_closed_timeout.
    type: str
    version_added: 0.2.0
  stream_bypass:
    description: The stream_bypass.
    type: str
    version_added: 0.2.0
  nfs_parser:
    description: The nfs_parser.
    type: str
    version_added: 0.2.0
  uuid:
    description: The uuid.
    type: str
    version_added: 0.2.0
  smtp_parser_extract_urls:
    description: The smtp_parser_extract_urls.
    type: str
    version_added: 0.2.0
  flow_tcp_new_timeout:
    description: The flow_tcp_new_timeout.
    type: str
    version_added: 0.2.0
  rule_sid_force_drop:
    description: The rule_sid_force_drop.
    type: str
    version_added: 0.2.0
  flow_icmp_emerg_established_timeout:
    description: The flow_icmp_emerg_established_timeout.
    type: str
    version_added: 0.2.0
  dns_parser_tcp:
    description: The dns_parser_tcp.
    type: str
    version_added: 0.2.0
  tls_ja3_fingerprint:
    description: The tls_ja3_fingerprint.
    type: str
    version_added: 0.2.0
  customrules:
    description: The customrules.
    type: str
    version_added: 0.2.0
  reassembly_to_server_chunk:
    description: The reassembly_to_server_chunk.
    type: str
    version_added: 0.2.0
  enable_async_sessions:
    description: The enable_async_sessions.
    type: str
    version_added: 0.2.0
  asn1_max_frames:
    description: The asn1_max_frames.
    type: str
    version_added: 0.2.0
  dns_parser_tcp_ports:
    description: The dns_parser_tcp_ports.
    type: str
    version_added: 0.2.0
  flow_icmp_emerg_new_timeout:
    description: The flow_icmp_emerg_new_timeout.
    type: str
    version_added: 0.2.0
  tls_detect_ports:
    description: The tls_detect_ports.
    type: str
    version_added: 0.2.0
  ip_max_trackers:
    description: The ip_max_trackers.
    type: str
    version_added: 0.2.0
  rdp_parser:
    description: The rdp_parser.
    type: str
    version_added: 0.2.0
  flow_icmp_new_timeout:
    description: The flow_icmp_new_timeout.
    type: str
    version_added: 0.2.0
  bittorrent_parser:
    description: The bittorrent_parser.
    type: str
    version_added: 0.2.0
  smtp_parser_decode_mime:
    description: The smtp_parser_decode_mime.
    type: str
    version_added: 0.2.0
  dns_parser_udp:
    description: The dns_parser_udp.
    type: str
    version_added: 0.2.0
  reassembly_depth:
    description: The reassembly_depth.
    type: str
    version_added: 0.2.0
  snmp_parser:
    description: The snmp_parser.
    type: str
    version_added: 0.2.0
  reassembly_memcap_policy:
    description: The reassembly_memcap_policy.
    type: str
    version_added: 0.2.0
  http_parser_memcap:
    description: The http_parser_memcap.
    type: str
    version_added: 0.2.0
  sip_parser:
    description: The sip_parser.
    type: str
    version_added: 0.2.0
  dns_parser_udp_ports:
    description: The dns_parser_udp_ports.
    type: str
    version_added: 0.2.0
  smtp_parser_decode_base64:
    description: The smtp_parser_decode_base64.
    type: str
    version_added: 0.2.0
  flow_prealloc:
    description: The flow_prealloc.
    type: str
    version_added: 0.2.0
  stream_memcap_policy:
    description: The stream_memcap_policy.
    type: str
    version_added: 0.2.0
  mqtt_parser:
    description: The mqtt_parser.
    type: str
    version_added: 0.2.0
'''

EXAMPLES = r'''
- name: Add myitem suricata interface
  pfsensible.suricata.pfsense_suricata_interface:
    descr: LAN
    enable: true
    interface: lan
    alertsystemlog: true
    alertsystemlog_facility: local1
    alertsystemlog_priority: notice
    enable_stats_collection: true
    rulesets:
      - decoder-events.rules
      - dns-events.rules
      - files.rules
      - http-events.rules
      - smtp-events.rules
      - stream-events.rules
      - tls-events.rules
      - GPLv2_community.rules
    rule_sid_off:
      - 1:2200075
      - 1:2210021
      - 1:2210044
      - 1:2210045
      - 1:2210029
      - 1:2210000
      - 1:2210026
      - 1:2210016
      - 1:2210039
      - 1:2210022
      - 1:2210015
    state: present

- name: Remove myitem suricata interface
  pfsensible.suricata.pfsense_suricata_interface:
    descr: LAN
    state: absent
'''
RETURN = r'''
commands:
    description: the set of commands that would be pushed to the remote device (if pfSense had a CLI).
    returned: always
    type: list
    sample: ["create suricata interface 'myitem'", "update suricata interface 'myitem' set ...", "delete suricata interface 'myitem'"]
interface:
    description: The pfSense name of the Suricata interface
    returned: always
    type: str
    sample: lan
interface_dev:
    description: The device name of the Suricata interface
    returned: always
    type: str
    sample: ix1
uuid:
    description: The UUID of the Suricata interface
    returned: always
    type: str
    sample: "39530"
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase
from ansible_collections.pfsensible.core.plugins.module_utils.arg_route import p2o_interface_without_virtual

SURICATA_INTERFACE_ARGUMENT_SPEC = dict(
    # Only descr should be required here - othewise you cannot remove an item with just 'descr'
    # Required arguments for creation should be noted in SURICATA_INTERFACE_REQUIRED_IF = ['state', 'present', ...] below
    interface=dict(type='str', required=True),
    descr=dict(required=True, type='str'),
    state=dict(type='str', default='present', choices=['present', 'absent']),
    enable=dict(type='bool'),
    alertsystemlog=dict(type='bool'),
    alertsystemlog_facility=dict(
        type='str',
        choices=[
            'auth', 'authpriv', 'daemon', 'kern', 'security', 'syslog', 'user', 'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7'
        ]
    ),
    alertsystemlog_priority=dict(type='str', choices=['emergency', 'critical', 'alert', 'error', 'warning', 'notice', 'info', 'debug']),
    enable_stats_collection=dict(type='bool'),
    stats_upd_interval=dict(type='int'),
    enable_stats_log=dict(type='bool'),
    append_stats_log=dict(type='bool'),
    enable_telegraf_stats=dict(type='bool'),
    enable_http_log=dict(type='bool'),
    append_http_log=dict(type='bool'),
    http_log_extended=dict(type='bool'),
    enable_tls_log=dict(type='bool'),
    enable_tls_store=dict(type='bool'),
    tls_log_extended=dict(type='bool'),
    enable_file_store=dict(type='bool'),
    file_store_logdir=dict(type='str'),
    enable_pcap_log=dict(type='bool'),
    max_pcap_log_size=dict(type='str'),
    max_pcap_log_files=dict(type='str'),
    enable_verbose_logging=dict(type='bool'),
    enable_eve_log=dict(type='bool'),
    eve_output_type=dict(type='str', choices=['regular', 'syslog', 'redis', 'unix_dgram', 'unix_stream']),
    eve_systemlog_facility=dict(
        type='str',
        choices=[
            'auth', 'authpriv', 'daemon', 'kern', 'security', 'syslog', 'user', 'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7'
        ]
    ),
    eve_systemlog_priority=dict(type='str', choices=['emerg', 'crit', 'alert', 'err', 'warning', 'notice', 'info']),
    eve_redis_server=dict(type='str'),
    eve_redis_port=dict(type='str'),
    eve_redis_mode=dict(type='str', choices=['list', 'rpush', 'channel']),
    eve_redis_key=dict(type='str', no_log=True),
    eve_log_alerts_xff=dict(type='bool'),
    eve_log_alerts_xff_mode=dict(type='str', choices=['extra-data', 'overwrite']),
    eve_log_alerts_xff_deployment=dict(type='str', choices=['reverse', 'forward']),
    eve_log_alerts_xff_header=dict(type='str'),
    eve_log_alerts=dict(type='bool'),
    eve_log_alerts_payload=dict(type='str', choices=['off', 'only-base64', 'only-printable', 'on']),
    eve_log_alerts_packet=dict(type='bool'),
    eve_log_alerts_http=dict(type='bool'),
    eve_log_alerts_metadata=dict(type='bool'),
    eve_log_anomaly=dict(type='bool'),
    eve_log_anomaly_type_decode=dict(type='bool'),
    eve_log_anomaly_type_stream=dict(type='bool'),
    eve_log_anomaly_type_applayer=dict(type='bool'),
    eve_log_anomaly_packethdr=dict(type='bool'),
    eve_log_dns=dict(type='bool'),
    eve_log_ftp=dict(type='bool'),
    eve_log_http=dict(type='bool'),
    eve_log_http2=dict(type='bool'),
    eve_log_ikev2=dict(type='bool'),
    eve_log_krb5=dict(type='bool'),
    eve_log_nfs=dict(type='bool'),
    eve_log_rdp=dict(type='bool'),
    eve_log_rfb=dict(type='bool'),
    eve_log_sip=dict(type='bool'),
    eve_log_smb=dict(type='bool'),
    eve_log_smtp=dict(type='bool'),
    eve_log_tftp=dict(type='bool'),
    eve_log_dhcp=dict(type='bool'),
    eve_log_drop=dict(type='bool'),
    eve_log_flow=dict(type='bool'),
    eve_log_mqtt=dict(type='bool'),
    eve_log_netflow=dict(type='bool'),
    eve_log_stats=dict(type='bool'),
    eve_log_snmp=dict(type='bool'),
    eve_log_ssh=dict(type='bool'),
    eve_log_tls=dict(type='bool'),
    eve_log_files=dict(type='bool'),
    eve_log_http_extended=dict(type='bool'),
    eve_log_tls_extended=dict(type='bool'),
    eve_log_dhcp_extended=dict(type='bool'),
    eve_log_smtp_extended=dict(type='bool'),
    eve_log_http_extended_headers=dict(type='list', elements='str'),
    eve_log_smtp_extended_fields=dict(type='list', elements='str'),
    eve_log_tls_extended_fields=dict(type='list', elements='str'),
    eve_log_files_magic=dict(type='bool'),
    eve_log_files_hash=dict(type='str', choices=['none', 'md5', 'sha1', 'sha256']),
    eve_log_stats_totals=dict(type='bool'),
    eve_log_stats_deltas=dict(type='bool'),
    eve_log_stats_threads=dict(type='bool'),
    blockoffenders=dict(type='bool'),
    ips_mode=dict(type='str', choices=['ips_mode_legacy', 'ips_mode_inline']),
    ips_netmap_threads=dict(type='str'),
    blockoffenderskill=dict(type='bool'),
    blockoffendersip=dict(type='str', choices=['src', 'dst', 'both']),
    block_drops_only=dict(type='bool'),
    passlistname=dict(type='str', choices=['default', 'none']),
    runmode=dict(type='str', choices=['autofp', 'workers', 'single']),
    autofp_scheduler=dict(type='str', choices=['hash', 'ippair']),
    max_pending_packets=dict(type='int'),
    detect_eng_profile=dict(type='str', choices=['low', 'medium', 'high']),
    mpm_algo=dict(type='str', choices=['auto', 'ac', 'ac-bs', 'ac-ks', 'hs']),
    sgh_mpm_context=dict(type='str', choices=['auto', 'full', 'single']),
    inspect_recursion_limit=dict(type='int'),
    delayed_detect=dict(type='bool'),
    intf_promisc_mode=dict(type='bool'),
    intf_snaplen=dict(type='int'),
    homelistname=dict(type='str', choices=['default']),
    externallistname=dict(type='str', choices=['default']),
    suppresslistname=dict(type='str'),
    flow_udp_emerg_established_timeout=dict(type='str'),
    flow_memcap=dict(type='str'),
    ssh_parser=dict(type='str'),
    ips_policy_enable=dict(type='str'),
    imap_parser=dict(type='str'),
    pgsql_parser=dict(type='str'),
    tls_parser=dict(type='str'),
    smtp_parser_decode_quoted_printable=dict(type='str'),
    smtp_parser=dict(type='str'),
    host_prealloc=dict(type='str'),
    quic_parser=dict(type='str'),
    http2_parser=dict(type='str'),
    ip_frag_timeout=dict(type='str'),
    reassembly_to_client_chunk=dict(type='str'),
    smtp_parser_compute_body_md5=dict(type='str'),
    stream_memcap=dict(type='str'),
    autoflowbitrules=dict(type='str'),
    ip_max_frags=dict(type='str'),
    stream_prealloc_sessions=dict(type='str'),
    dns_request_flood_limit=dict(type='str'),
    smb_parser=dict(type='str'),
    rulesets=dict(type='list', elements='str'),
    defrag_memcap_policy=dict(type='str'),
    tls_encrypt_handling=dict(type='str'),
    flow_tcp_emerg_closed_timeout=dict(type='str'),
    flow_memcap_policy=dict(type='str'),
    frag_hash_size=dict(type='str'),
    telnet_parser=dict(type='str'),
    stream_checksum_validation=dict(type='str'),
    reassembly_memcap=dict(type='str'),
    ntp_parser=dict(type='str'),
    enable_dns_log=dict(type='str'),
    flow_prune=dict(type='str'),
    max_synack_queued=dict(type='str'),
    host_os_policy=dict(type='str'),
    flow_tcp_established_timeout=dict(type='str'),
    append_dns_log=dict(type='str'),
    dns_state_memcap=dict(type='str'),
    host_memcap=dict(type='str'),
    host_hash_size=dict(type='str'),
    flow_udp_new_timeout=dict(type='str'),
    ftp_parser=dict(type='str'),
    dhcp_parser=dict(type='str'),
    rfb_parser=dict(type='str'),
    app_layer_error_policy=dict(type='str'),
    dcerpc_parser=dict(type='str'),
    enable_tracked_files_md5=dict(type='str'),
    enip_parser=dict(type='str'),
    rule_sid_off=dict(type='list', elements='str'),
    flow_hash_size=dict(type='str'),
    ikev2_parser=dict(type='str'),
    enable_midstream_sessions=dict(type='str'),
    flow_tcp_emerg_established_timeout=dict(type='str'),
    flow_udp_established_timeout=dict(type='str'),
    flow_emerg_recovery=dict(type='str'),
    flow_tcp_emerg_new_timeout=dict(type='str'),
    flow_icmp_established_timeout=dict(type='str'),
    http_parser=dict(type='str'),
    msn_parser=dict(type='str'),
    frag_memcap=dict(type='str'),
    flow_udp_emerg_new_timeout=dict(type='str'),
    stream_drop_invalid=dict(type='str'),
    enable_iprep=dict(type='str'),
    libhtp_policy=dict(type='str'),
    midstream_policy=dict(type='str'),
    dns_global_memcap=dict(type='str'),
    flow_tcp_closed_timeout=dict(type='str'),
    stream_bypass=dict(type='str', no_log=False),
    nfs_parser=dict(type='str'),
    uuid=dict(type='str'),
    smtp_parser_extract_urls=dict(type='str'),
    flow_tcp_new_timeout=dict(type='str'),
    rule_sid_force_drop=dict(type='str'),
    flow_icmp_emerg_established_timeout=dict(type='str'),
    dns_parser_tcp=dict(type='str'),
    tls_ja3_fingerprint=dict(type='str'),
    customrules=dict(type='str'),
    reassembly_to_server_chunk=dict(type='str'),
    enable_async_sessions=dict(type='str'),
    asn1_max_frames=dict(type='str'),
    dns_parser_tcp_ports=dict(type='str'),
    flow_icmp_emerg_new_timeout=dict(type='str'),
    tls_detect_ports=dict(type='str'),
    ip_max_trackers=dict(type='str'),
    rdp_parser=dict(type='str'),
    flow_icmp_new_timeout=dict(type='str'),
    bittorrent_parser=dict(type='str'),
    smtp_parser_decode_mime=dict(type='str'),
    dns_parser_udp=dict(type='str'),
    reassembly_depth=dict(type='str'),
    snmp_parser=dict(type='str'),
    reassembly_memcap_policy=dict(type='str'),
    http_parser_memcap=dict(type='str'),
    sip_parser=dict(type='str'),
    dns_parser_udp_ports=dict(type='str'),
    smtp_parser_decode_base64=dict(type='str'),
    flow_prealloc=dict(type='str'),
    stream_memcap_policy=dict(type='str'),
    mqtt_parser=dict(type='str'),
)

SURICATA_INTERFACE_REQUIRED_IF = [
    ['state', 'present', ['descr', 'interface']],
]

SURICATA_INTERFACE_ARG_ROUTE = dict(
    interface=dict(parse=p2o_interface_without_virtual,),
)

SURICATA_INTERFACE_CREATE_DEFAULT = dict(
    enable_verbose_logging='off',
    max_pcap_log_size='32',
    max_pcap_log_files='100',
    pcap_log_conditional='alerts',
    enable_stats_collection='off',
    enable_stats_log='off',
    append_stats_log='off',
    stats_upd_interval='10',
    enable_telegraf_stats='off',
    enable_http_log='on',
    append_http_log='on',
    enable_tls_log='off',
    append_tls_log='on',
    enable_tls_store='off',
    http_log_extended='on',
    tls_log_extended='on',
    tls_session_resumption='off',
    enable_pcap_log='off',
    pcap_use_stream_depth='off',
    pcap_honor_pass_rules='off',
    enable_file_store='off',
    tls_log_filetype='regular',
    http_log_filetype='regular',
    runmode='autofp',
    autofp_scheduler='hash',
    max_pending_packets='1024',
    inspect_recursion_limit='3000',
    intf_snaplen='1518',
    detect_eng_profile='medium',
    mpm_algo='auto',
    spm_algo='auto',
    sgh_mpm_context='auto',
    blockoffenders='off',
    ips_mode='ips_mode_legacy',
    ips_netmap_threads='auto',
    blockoffenderskill='on',
    block_drops_only='off',
    passlist_debug_log='off',
    blockoffendersip='both',
    passlistname='default',
    homelistname='default',
    externallistname='default',
    suppresslistname='default',
    alertsystemlog='off',
    alertsystemlog_facility='local1',
    alertsystemlog_priority='notice',
    enable_eve_log='off',
    eve_output_type='regular',
    eve_systemlog_facility='local1',
    eve_systemlog_priority='notice',
    eve_log_ethernet='no',
    eve_log_alerts='on',
    eve_log_alerts_payload='on',
    eve_log_alerts_packet='on',
    eve_log_alerts_metadata='on',
    eve_log_alerts_http='on',
    eve_log_alerts_xff='off',
    eve_log_alerts_xff_mode='extra-data',
    eve_log_alerts_xff_deployment='reverse',
    eve_log_alerts_xff_header='X-Forwarded-For',
    eve_log_alerts_verdict='off',
    eve_log_alerts_tagged='off',
    eve_log_drops='on',
    eve_log_alert_drops='on',
    eve_log_drops_verdict='off',
    eve_log_drops_flows='all',
    eve_log_anomaly='off',
    eve_log_anomaly_type_decode='off',
    eve_log_anomaly_type_stream='off',
    eve_log_anomaly_type_applayer='on',
    eve_log_anomaly_packethdr='off',
    eve_log_http='on',
    eve_log_dns='on',
    eve_log_tls='on',
    eve_log_dhcp='on',
    eve_log_nfs='on',
    eve_log_smb='on',
    eve_log_krb5='on',
    eve_log_ikev2='on',
    eve_log_tftp='on',
    eve_log_bittorrent='off',
    eve_log_pgsql='off',
    eve_log_quic='on',
    eve_log_rdp='off',
    eve_log_sip='off',
    eve_log_files='on',
    eve_log_ssh='on',
    eve_log_smtp='on',
    eve_log_stats='off',
    eve_log_flow='off',
    eve_log_netflow='off',
    eve_log_snmp='on',
    eve_log_mqtt='on',
    eve_log_ftp='on',
    eve_log_http2='on',
    eve_log_rfb='on',
    eve_log_stats_totals='on',
    eve_log_stats_deltas='off',
    eve_log_stats_threads='off',
    eve_log_http_extended='on',
    eve_log_tls_extended='on',
    eve_log_dhcp_extended='off',
    eve_log_smtp_extended='on',
    eve_log_http_extended_headers=(
        "accept, accept-charset, accept-datetime, accept-encoding, accept-language, accept-range, age, allow, authorization, cache-control, connection, "
        "content-encoding, content-language, content-length, content-location, content-md5, content-range, content-type, cookie, date, dnt, etags, "
        "from, last-modified, link, location, max-forwards, origin, pragma, proxy-authenticate, proxy-authorization, range, referrer, refresh, retry-after, "
        "server, set-cookie, te, trailer, transfer-encoding, upgrade, vary, via, warning, www-authenticate, x-authenticated-user, x-flash-version, "
        "x-forwarded-proto, x-requested-with"
    ),
    eve_log_smtp_extended_fields='bcc, received, reply-to, x-mailer, x-originating-ip',
    eve_log_tls_extended_fields='',
    eve_log_files_magic='off',
    eve_log_files_hash='none',
    eve_log_drop='on',
    delayed_detect='off',
    intf_promisc_mode='on',
    eve_redis_server='127.0.0.1',
    eve_redis_port='6379',
    eve_redis_mode='list',
    eve_redis_key='suricata',
    ip_max_frags='65535',
    ip_frag_timeout='60',
    frag_memcap='33554432',
    defrag_memcap_policy='ignore',
    ip_max_trackers='65535',
    frag_hash_size='65536',
    flow_memcap='134217728',
    flow_memcap_policy='ignore',
    flow_prealloc='10000',
    flow_hash_size='65536',
    flow_emerg_recovery='30',
    flow_prune='5',
    flow_tcp_new_timeout='60',
    flow_tcp_established_timeout='3600',
    flow_tcp_closed_timeout='120',
    flow_tcp_emerg_new_timeout='10',
    flow_tcp_emerg_established_timeout='300',
    flow_tcp_emerg_closed_timeout='20',
    flow_udp_new_timeout='30',
    flow_udp_established_timeout='300',
    flow_udp_emerg_new_timeout='10',
    flow_udp_emerg_established_timeout='100',
    flow_icmp_new_timeout='30',
    flow_icmp_established_timeout='300',
    flow_icmp_emerg_new_timeout='10',
    flow_icmp_emerg_established_timeout='100',
    stream_memcap='268435456',
    stream_prealloc_sessions='32768',
    reassembly_memcap='131217728',
    reassembly_depth='1048576',
    reassembly_to_server_chunk='2560',
    reassembly_to_client_chunk='2560',
    max_synack_queued='5',
    enable_midstream_sessions='off',
    stream_memcap_policy='ignore',
    reassembly_memcap_policy='ignore',
    midstream_policy='ignore',
    stream_checksum_validation='off',
    enable_async_sessions='off',
    stream_bypass='off',
    stream_drop_invalid='off',
    app_layer_error_policy='ignore',
    asn1_max_frames='256',
    bittorrent_parser='yes',
    dcerpc_parser='yes',
    dhcp_parser='yes',
    dns_global_memcap='16777216',
    dns_state_memcap='524288',
    dns_request_flood_limit='500',
    dns_parser_udp='yes',
    dns_parser_tcp='yes',
    dns_parser_udp_ports='53',
    dns_parser_tcp_ports='53',
    enip_parser='yes',
    ftp_parser='yes',
    ftp_data_parser='on',
    http_parser='yes',
    http_parser_memcap='67108864',
    http2_parser='yes',
    ikev2_parser='yes',
    imap_parser='detection-only',
    krb5_parser='yes',
    mqtt_parser='yes',
    msn_parser='detection-only',
    nfs_parser='yes',
    ntp_parser='yes',
    pgsql_parser='no',
    quic_parser='yes',
    rdp_parser='yes',
    rfb_parser='yes',
    sip_parser='yes',
    smb_parser='yes',
    smtp_parser='yes',
    smtp_parser_decode_mime='off',
    smtp_parser_decode_base64='on',
    smtp_parser_decode_quoted_printable='on',
    smtp_parser_extract_urls='on',
    smtp_parser_compute_body_md5='off',
    snmp_parser='yes',
    ssh_parser='yes',
    telnet_parser='yes',
    tftp_parser='yes',
    tls_parser='yes',
    tls_detect_ports='443',
    tls_encrypt_handling='default',
    tls_ja3_fingerprint='off',
    enable_iprep='off',
    host_memcap='33554432',
    host_hash_size='4096',
    host_prealloc='1000',
    host_os_policy=dict(item=dict(name='default', bind_to='all', policy='bsd')),
    libhtp_policy={
        'item': {
            'name': 'default', 'bind_to': 'all', 'personality': 'IDS', 'request-body-limit': '4096', 'response-body-limit': '4096',
            'double-decode-path': 'no', 'double-decode-query': 'no', 'uri-include-all': 'no', 'meta-field-limit': '18432',
        }
    },
    rulesets=(
        "app-layer-events.rules||decoder-events.rules||dhcp-events.rules||dnp3-events.rules||dns-events.rules||files.rules||ftp-events.rules||"
        "http-events.rules||http2-events.rules||ipsec-events.rules||kerberos-events.rules||modbus-events.rules||mqtt-events.rules||nfs-events.rules||"
        "ntp-events.rules||quic-events.rules||rfb-events.rules||smb-events.rules||smtp-events.rules||ssh-events.rules||stream-events.rules||tls-events.rules"
    ),
)

SURICATA_INTERFACE_PHP_COMMAND_SET = r'''
require_once("/usr/local/pkg/suricata/suricata.inc");
sync_suricata_package_config();
'''


class PFSenseSuricataInterfaceModule(PFSenseModuleBase):
    """ module managing pfsense suricata interfaces """

    ##############################
    # unit tests
    #
    # Must be class method for unit test usage
    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return SURICATA_INTERFACE_ARGUMENT_SPEC

    def __init__(self, module, pfsense=None):
        super(PFSenseSuricataInterfaceModule, self).__init__(module, pfsense, package='suricata', root='suricata', node='rule', key='descr',
                                                             arg_route=SURICATA_INTERFACE_ARG_ROUTE, bool_style='on',
                                                             create_default=SURICATA_INTERFACE_CREATE_DEFAULT)

    ##############################
    # run
    #
    def _run_post(self):
        """ used to do some post-processing like adding results or decoding diff entries """
        self.result['uuid'] = self.diff['after']['uuid']
        self.result['interface'] = self.diff['after']['interface']
        self.result['interface_dev'] = self.pfsense.get_interface_port(self.diff['after']['interface'])

    ##############################
    # XML processing
    #
    def suricata_generate_id(self):
        return str(self.pfsense.php("require_once('/usr/local/pkg/suricata/suricata.inc');echo json_encode(suricata_generate_id());"))

    def _create_target(self):
        """ create the XML target_elt """
        self.obj['uuid'] = self.suricata_generate_id()
        return super(PFSenseSuricataInterfaceModule, self)._create_target()

    def _copy_and_update_target(self):
        """ update the XML target_elt """
        (before, changed) = super(PFSenseSuricataInterfaceModule, self)._copy_and_update_target()
        if self.diff['after'].get('rule_sid_off') is not None:
            self.diff['after']['rule_sid_off'] = sorted(self.diff['after']['rule_sid_off'].split('||'))
        if self.diff['before'].get('rule_sid_off') is not None:
            self.diff['before']['rule_sid_off'] = sorted(self.diff['before']['rule_sid_off'].split('||'))
        if self.diff['after'].get('rulesets') is not None:
            self.diff['after']['rulesets'] = sorted(self.diff['after']['rulesets'].split('||'))
        if self.diff['before'].get('rulesets') is not None:
            self.diff['before']['rulesets'] = sorted(self.diff['before']['rulesets'].split('||'))
        return (before, changed)

    ##############################
    # run
    #

    def _update(self):
        """ make the target pfsense reload """
        return self.pfsense.phpshell(SURICATA_INTERFACE_PHP_COMMAND_SET)


def main():
    module = AnsibleModule(
        argument_spec=SURICATA_INTERFACE_ARGUMENT_SPEC,
        required_if=SURICATA_INTERFACE_REQUIRED_IF,
        supports_check_mode=True)

    pfmodule = PFSenseSuricataInterfaceModule(module)
    # Pass params for testing framework
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
