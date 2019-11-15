module Dradis::Plugins::Nessus
  class Importer < Dradis::Plugins::Upload::Importer

    # The framework will call this function if the user selects this plugin from
    # the dropdown list and uploads a file.
    # @returns true if the operation was successful, false otherwise
    def import(params={})
      file_content = File.read(params[:file])

      logger.info { 'Parsing nessus output file...' }
      Nokogiri::XML::Reader(file_content).each do |node|
        if node.name == 'ReportHost' && node.node_type == Nokogiri::XML::Reader::TYPE_ELEMENT
          process_report_host(Nokogiri::XML(node.outer_xml).at('./ReportHost'))
        end
      end
      logger.info { 'Done.' }

      true
    end # /import


    private

    # Internal: Parses the specific "Nessus SYN Scanner" and similar plugin into
    # Dradis node properties.
    #
    # host_node       - The Dradis Node that represents the host in the project.
    # xml_report_item - The Nokogiri XML node representing the Service Detection
    #                   <ReportItem> tag.
    #
    # Returns nothing.
    #
    # Plugins processed using this method:
    #   - [11219] Nessus SYN Scanner
    #   - [34220] Netstat Portscanner (WMI)
    def process_nessus_syn_scanner(host_node, xml_report_item)
      process_service(
        host_node,
        xml_report_item,
        { 'syn-scanner' => xml_report_item.at_xpath('./plugin_output').try(:text)}
      )
    end

    # Internal: Process each /NessusClientData_v2/Report/ReportHost creating a
    # Dradis node and adding some properties to it (:ip, :os, etc.).
    #
    # xml_host        - The Nokogiri XML node representing the parent host for
    #                   this issue.
    #
    # Returns nothing.
    #
    def process_report_host(xml_host)

      # 1. Create host node
      host_label = xml_host.attributes['name'].value
      host_label += " (#{xml_host.attributes['fqdn'].value})" if xml_host.attributes['fqdn']

      host_node = content_service.create_node(label: host_label, type: :host)
      logger.info{ "\tHost: #{host_label}" }

      # 2. Add host info note and host properties
      host_note_text = template_service.process_template(template: 'report_host', data: xml_host)
      content_service.create_note(text: host_note_text, node: host_node)

      if host_node.respond_to?(:properties)
        nh = ::Nessus::Host.new(xml_host)
        host_node.set_property(:fqdn,         nh.fqdn)             if nh.try(:fqdn)
        host_node.set_property(:ip,           nh.ip)               if nh.try(:ip)
        host_node.set_property(:mac_address,  nh.mac_address)      if nh.try(:mac_address)
        host_node.set_property(:netbios_name, nh.netbios_name)     if nh.try(:netbios_name)
        host_node.set_property(:os,           nh.operating_system) if nh.try(:operating_system)
        host_node.save
      end


      # 3. Add Issue and associated Evidence for this host/port combination
      xml_host.xpath('./ReportItem').each do |xml_report_item|
        case xml_report_item.attributes['pluginID'].value
        when '0'
        when '11219', '34220' # Nessus SYN scanner, Netstat Portscanner (WMI)
          process_nessus_syn_scanner(host_node, xml_report_item)
        when '22964' # Service Detection
          process_service_detection(host_node, xml_report_item)
        else
          process_report_item(xml_host, host_node, xml_report_item)
        end
      end #/ReportItem
    end

    # Internal: Process each /NessusClientData_v2/Report/ReportHost/ReportItem
    # and creates the corresponding Issue and Evidence in Dradis.
    #
    # xml_host        - The Nokogiri XML node representing the parent host for
    #                   this issue.
    # host_node       - The Dradis Node that represents the host in the project.
    # xml_report_item - The Nokogiri XML node representing the Service Detection
    #                   <ReportItem> tag.
    #
    # Returns nothing.
    #
    def process_report_item(xml_host, host_node, xml_report_item)
      # 3.1. Add Issue to the project
      plugin_id = xml_report_item.attributes['pluginID'].value
      logger.info{ "\t\t => Creating new issue (plugin_id: #{plugin_id})" }

      issue_text = template_service.process_template(template: 'report_item', data: xml_report_item)

      issue = content_service.create_issue(text: issue_text, id: plugin_id)

      # 3.2. Add Evidence to link the port/protocol and Issue
      port_info = xml_report_item.attributes['protocol'].value
      port_info += "/"
      port_info += xml_report_item.attributes['port'].value

      logger.info{ "\t\t\t => Adding reference to this host" }
      evidence_content = template_service.process_template(template: 'evidence', data: xml_report_item)

      content_service.create_evidence(issue: issue, node: host_node, content: evidence_content)

      # 3.3. Compliance check information
    end

    # Internal: Parses the specific "Service Detection" plugin into Dradis node
    # properties.
    #
    # host_node       - The Dradis Node that represents the host in the project.
    # xml_report_item - The Nokogiri XML node representing the Service Detection
    #                   <ReportItem> tag.
    #
    # Returns nothing.
    #
    def process_service_detection(host_node, xml_report_item)
      output = xml_report_item.at_xpath('./plugin_output').try(:text) || xml_report_item.at_xpath('./description').try(:text)
      process_service(
        host_node,
        xml_report_item,
        { 'service-detection' => output }
      )
    end

    def process_service(host_node, xml_report_item, service_extra)
      name     = xml_report_item['svc_name']
      port     = xml_report_item['port'].to_i
      protocol = xml_report_item['protocol']
      logger.info { "\t\t => Creating new service: #{protocol}/#{port}" }

      host_node.set_service(
        service_extra.merge({
          name: name,
          port: port,
          protocol: protocol,
          state: :open,
          source: :nessus
        })
      )

      host_node.save
    end
  end
end
