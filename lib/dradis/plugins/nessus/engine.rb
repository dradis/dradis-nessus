module Dradis
  module Plugins
    module Nessus
      class Engine < ::Rails::Engine
        isolate_namespace Dradis::Plugins::Nessus

        include ::Dradis::Plugins::Base
        description 'Processes Nessus XML v2 format (.nessus)'
        provides :upload

        initializer 'nessus.asset_paths' do |app|
          app.config.assets.paths << root.join('app/javascript')
          app.config.assets.precompile += %w[
            dradis/plugins/nessus/upload_detectors/nessus.js
          ]
        end

        initializer 'nessus.importmap', before: 'importmap' do |app|
          app.config.importmap.paths << root.join('config/importmap.rb')
          app.config.importmap.cache_sweepers << root.join('app/javascript')
        end

        def self.upload_detectors
          ['dradis/plugins/nessus/upload_detectors/nessus']
        end
      end
    end
  end
end
