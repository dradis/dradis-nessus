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
  end
end
