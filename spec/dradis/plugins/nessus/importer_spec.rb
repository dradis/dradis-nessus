require 'spec_helper'
require 'ostruct'

describe Dradis::Plugins::Nessus::Importer do
  before(:each) do
    mapping_service = double('Dradis::Plugins::MappingService')
    allow(mapping_service).to receive(:apply_mapping).and_return('')
    allow(Dradis::Plugins::MappingService).to receive(:new).and_return(mapping_service)

    # Init services
    plugin = Dradis::Plugins::Nessus

    @content_service = Dradis::Plugins::ContentService::Base.new(
      logger: Logger.new(STDOUT),
      plugin: plugin
    )

    @importer = plugin::Importer.new(
      content_service: @content_service
    )

    # Stub dradis-plugins methods
    #
    # They return their argument hashes as objects mimicking
    # Nodes, Issues, etc
    allow(@content_service).to receive(:create_node) do |args|
      obj = OpenStruct.new(args)
      obj.define_singleton_method(:set_property) { |*| }
      obj.define_singleton_method(:set_service) { |*| }
      obj
    end
    allow(@content_service).to receive(:create_note) do |args|
      OpenStruct.new(args)
    end
  end

  it "creates one node for each host" do
    %w{snorby.org scanme.insecure.org}.each do |host|
      expect(@content_service).to receive(:create_node).with(hash_including label: host).once
    end

    allow(@content_service).to receive(:create_evidence) do |args|
      OpenStruct.new(args)
    end
    allow(@content_service).to receive(:create_issue) do |args|
      OpenStruct.new(args)
    end

    # Run the import
    @importer.import(file: 'spec/fixtures/files/example_v2.nessus')
  end
end
