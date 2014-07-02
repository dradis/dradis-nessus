require 'dradis/plugins/nessus/engine'
require 'dradis/plugins/nessus/field_processor'
require 'dradis/plugins/nessus/importer'
require 'dradis/plugins/nessus/version'

module Dradis
  module Plugins
    module Nessus

      # This is required while we transition the Upload Manager to use
      # Dradis::Plugins
      module Meta
        NAME = "Nessus output (.nessus) file upload"
        EXPECTS = "Nessus XML (V2) format."
        module VERSION
          include Dradis::Plugins::Nessus::VERSION
        end
      end
    end
  end
end