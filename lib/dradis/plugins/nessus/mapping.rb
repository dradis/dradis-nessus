module Dradis::Plugins::Nessus
  module Mapping
    DEFAULT_MAPPING = {
      evidence: {
        'Location' => '{{ nessus[evidence.protocol] }}/{{ nessus[evidence.port] }}',
        'Output' => 'bc.. {{ nessus[evidence.plugin_output] }}'
      },
      report_host: {
        'Title' => 'Nessus host summary',
        'Host information' => "Name: {{ nessus[report_host.name] }}\n
                              IP address: {{ nessus[report_host.ip] }}\n
                              FQDN: {{ nessus[report_host.fqdn] }}\n
                              OS: {{ nessus[report_host.operating_system] }}\n
                              Mac address: {{ nessus[report_host.mac_address] }}\n
                              Netbios name: {{ nessus[report_host.netbios_name] }}",
        'Scan information' => "Scan started: {{ nessus[report_host.scan_start_time] }}\n
                              Scan ended: {{ nessus[report_host.scan_stop_time] }}"
      },
      report_item: {
        'Title' => '{{ nessus[report_item.plugin_name] }}',
        'CVSSv3.BaseScore' => '{{ nessus[report_item.cvss3_base_score] }}',
        'CVSSv3Vector' => '{{ nessus[report_item.cvss3_vector] }}',
        'Type' => 'Internal',
        'Description' => '{{ nessus[report_item.description] }}',
        'Solution' => '{{ nessus[report_item.solution] }}',
        'References' => '{{ nessus[report_item.see_also_entries] }}'
      }
    }.freeze

    SOURCE_FIELDS = {
      evidence: [
        'compliance.cm_actual_value',
        'compliance.cm_audit_file',
        'compliance.cm_check_id',
        'compliance.cm_check_name',
        'compliance.cm_info',
        'compliance.cm_output',
        'compliance.cm_policy_value',
        'compliance.cm_reference',
        'compliance.cm_result',
        'compliance.cm_see_also',
        'compliance.cm_solution',
        'evidence.plugin_output',
        'evidence.port',
        'evidence.protocol',
        'evidence.svc_name',
        'evidence.severity',
        'report_item.plugin_name'
      ],
      report_host: [
        'report_host.name',
        'report_host.ip',
        'report_host.fqdn',
        'report_host.operating_system',
        'report_host.mac_address',
        'report_host.netbios_name',
        'report_host.scan_start_time',
        'report_host.scan_stop_time'
      ],
      report_item: [
        'report_item.age_of_vuln',
        'report_item.bid_entries',
        'report_item.cve_entries',
        'report_item.cvss3_base_score',
        'report_item.cvss3_impact_score',
        'report_item.cvss3_temporal_score',
        'report_item.cvss3_temporal_vector',
        'report_item.cvss3_vector',
        'report_item.cvss_base_score',
        'report_item.cvss_temporal_score',
        'report_item.cvss_temporal_vector',
        'report_item.cvss_vector',
        'report_item.description',
        'report_item.exploitability_ease',
        'report_item.exploit_available',
        'report_item.exploit_code_maturity',
        'report_item.exploit_framework_canvas',
        'report_item.exploit_framework_core',
        'report_item.exploit_framework_metasploit',
        'report_item.metasploit_name',
        'report_item.patch_publication_date',
        'report_item.plugin_family',
        'report_item.plugin_id',
        'report_item.plugin_modification_date',
        'report_item.plugin_name',
        'report_item.plugin_output',
        'report_item.plugin_publication_date',
        'report_item.plugin_type',
        'report_item.plugin_version',
        'report_item.port',
        'report_item.product_coverage',
        'report_item.protocol',
        'report_item.risk_factor',
        'report_item.see_also_entries',
        'report_item.severity',
        'report_item.solution',
        'report_item.svc_name',
        'report_item.synopsis',
        'report_item.threat_intensity_last_28',
        'report_item.threat_recency',
        'report_item.threat_sources_last_28',
        'report_item.vpr_score',
        'report_item.vuln_publication_date',
        'report_item.xref_entries'
      ]
    }.freeze
  end
end
