module Nessus
  # This class represents each of the /NessusClientData_v2/Report/ReportHost
  # elements in the Nessus XML document.
  #
  # It provides a convenient way to access the information scattered all over
  # the XML in attributes and nested tags.
  #
  # Instead of providing separate methods for each supported property we rely
  # on Ruby's #method_missing to do most of the work.
  class Host
    # Accepts an XML node from Nokogiri::XML.
    def initialize(xml_node)
      @xml = xml_node
      @report_item = report_items.first
    end

    # List of supported tags. They are all desdendents of the ./HostProperties
    # node.
    def supported_tags
      [
        # attributes
        :name,

        # simple tags
        :ip, :fqdn, :operating_system, :mac_address, :netbios_name,
        :scan_start_time, :scan_stop_time
      ]
    end

    # Each of the entries associated with this host. Returns an array of
    # Nessus::ReportItem objects
    def report_items
      @xml.xpath('./ReportItem').collect { |xml_report_item| ReportItem.new(xml_report_item) }
    end

    # This allows external callers (and specs) to check for implemented
    # properties
    def respond_to?(method, include_private=false)
      return true if supported_tags.include?(method.to_sym) || @report_item.respond_to?(method)
      super
    end

    # This method is invoked by Ruby when a method that is not defined in this
    # instance is called.
    #
    # In our case we inspect the @method@ parameter and try to find the
    # corresponding <tag/> element inside the ./HostProperties child.
    def method_missing(method, *args)
      # We could remove this check and return nil for any non-recognized tag.
      # The problem would be that it would make tricky to debug problems with
      # typos. For instance: <>.potr would return nil instead of raising an
      # exception
      unless supported_tags.include?(method) || @report_item.respond_to?(method)
        super
        return
      end

      # first we try the attributes: name
      translations_table = {}
      method_name = translations_table.fetch(method, method.to_s)
      return @xml.attributes[method_name].value if @xml.attributes.key?(method_name)

      # return the report_item field if it's a report_item method
      return @report_item.send(method_name) if @report_item.respond_to?(method_name)

      # translation of Host properties
      translations_table = {
        ip:               'host-ip',
        fqdn:             'host-fqdn',
        operating_system: 'operating-system',
        mac_address:      'mac-address',
        netbios_name:     'netbios-name',
        scan_start_time:  'HOST_START',
        scan_stop_time:   'HOST_END'
      }
      method_name = translations_table.fetch(method, method.to_s)

      if property = @xml.at_xpath("./HostProperties/tag[@name='#{method_name}']")
        return property.text
      else
        return nil
      end
    end
  end
end
