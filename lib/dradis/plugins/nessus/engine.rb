module Dradis
  module Plugins
    module Nessus
      class Engine < ::Rails::Engine
        isolate_namespace Dradis::Plugins::Nessus

        include ::Dradis::Plugins::Base
        provides :upload

        # plugin_info provides: :upload,
        #   description: 'Nessus output (.nessus) file upload',
        #   expects: 'Nessus XML (v2) format'
        # NAME = "Nessus output (.nessus) file upload"
        # EXPECTS = "Nessus XML (V2) format."


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