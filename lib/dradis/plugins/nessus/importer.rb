module Dradis
  module Plugins
    module Nessus
      class Importer < Dradis::Plugins::Upload::Base

        # The framework will call this function if the user selects this plugin from
        # the dropdown list and uploads a file.
        # @returns true if the operation was successful, false otherwise
        def import(params={})
          file_content    = File.read( params[:file] )

          logger.info{'Parsing nessus output file...'}
          doc = Nokogiri::XML( file_content )
          logger.info{'Done.'}

          if doc.xpath('/NessusClientData_v2/Report').empty?
            error = "No reports were detected in the uploaded file (/NessusClientData_v2/Report). Ensure you uploaded a Nessus XML v2 (.nessus) report."
            logger.fatal{ error }
            content_service.create_note text: error
            return false
          end

          # This holds a collection of issues by their nessus pluginID. We first
          # lookup the Issues already in the report and then we keep adding new ones
          # that appear in the uploaded file
          issues = content_service.all_issues_by_field('PluginID')

          # This will be filled in by the Processor for each item in the report
          host_note_text = nil
          issue_text = nil
          evidence_content = nil

          doc.xpath('/NessusClientData_v2/Report').each do |xml_report|
            report_label = xml_report.attributes['name'].value
            logger.info{ "Processing report: #{report_label}" }
            # No need to create a report node for each report. It may be good to
            # create a plugin.output/nessus.reports with info for each scan, but
            # for the time being we just append stuff to the Host
            # report_node = parent.children.find_or_create_by_label(report_label)

            # 1. Create a note with Host properties
            xml_report.xpath('./ReportHost').each do |xml_host|
              host_label = xml_host.attributes['name'].value
              host_label += " (#{xml_host.attributes['fqdn'].value})" if xml_host.attributes['fqdn']

              host_node = content_service.create_node(label: host_label, type_id: Node::Types::HOST)
              logger.info{ "\tHost: #{host_label}" }

              host_note_text = template_service.process_template(template: 'report_host', data: xml_host)
              content_service.create_note(text: host_note_text, node: host_node)


              # 2. Add Issue and associated Evidence for this host/port combination
              xml_host.xpath('./ReportItem').each do |xml_report_item|
                next if xml_report_item.attributes['pluginID'].value == "0"

                # 2.1 Find out if we already have this Issue:
                #       - If not, create it
                #       - If yes, obtain a reference
                plugin_id = xml_report_item.attributes['pluginID'].value
                logger.info{ "\n\nPluginID: #{plugin_id}" }

                if !issues.key?(plugin_id)
                  logger.info{ "\t\t\t => Creating new issue" }
                  issue_text = template_service.process_template(template: 'report_item', data: xml_report_item)
                  issue_text << "\n#[Host]#\n#{xml_host.attributes['name']}\n\n"
                  issue_text << "\n#[PluginID]#\n#{plugin_id}\n\n"

                  issues[plugin_id] = content_service.create_issue(text: issue_text)
                end

                # 2.2 Add Evidence to link the port/protocol and Issue
                port_info = xml_report_item.attributes['protocol'].value
                port_info += "/"
                port_info += xml_report_item.attributes['port'].value

                logger.info{ "\t\t\t => Adding reference to this host" }
                evidence_content = "\n#[Port]#\n#{port_info}\n\n"
                evidence_content << "\n#[Output]#\nbc.. "
                if (plugin_output = xml_report_item.xpath('./plugin_output/text()')[0])
                  evidence_content << plugin_output.content
                else
                  evidence_content << 'N/A'
                end
                evidence_content << "\n\n"

                content_service.create_evidence(issue: issues[plugin_id], node: host_node, content: evidence_content)
              end #/ReportItem

            end #/ReportHost
            logger.info{ "Report processed." }
          end  #/Report

          return true
        end # /import
      end
    end
  end
end