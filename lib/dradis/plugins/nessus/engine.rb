module Dradis
  module Plugins
    module Nessus
      class Engine < ::Rails::Engine
        isolate_namespace Dradis::Plugins::Nessus

        include ::Dradis::Plugins::Base
        description 'Processes Nessus XML v2 format (.nessus)'
        provides :upload

        #     generators do
        #       require "path/to/my_railtie_generator"
        #     end

        # Configuring the gem
        # class Configuration < Core::Configurator
        #   configure :namespace => 'burp'
        #   setting :category, :default => 'Burp Scanner output'
        #   setting :author, :default => 'Burp Scanner plugin'
        # end
      end
    end
  end
end