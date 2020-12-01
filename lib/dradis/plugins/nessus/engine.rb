module Dradis
  module Plugins
    module Nessus
      class Engine < ::Rails::Engine
        isolate_namespace Dradis::Plugins::Nessus

        include ::Dradis::Plugins::Base
        description 'Processes Nessus XML v2 format (.nessus)'
        provides :upload
      end
    end
  end
end
