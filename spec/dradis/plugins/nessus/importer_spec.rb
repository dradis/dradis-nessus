require 'spec_helper'
require 'ostruct'

describe Dradis::Plugins::Nessus::Importer do

  before(:each) do
    # Stub template service
    templates_dir = File.expand_path('../../../../../templates', __FILE__)
    expect_any_instance_of(Dradis::Plugins::TemplateService)
    .to receive(:default_templates_dir).and_return(templates_dir)

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

  it 'creates one node for each host' do
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

  describe 'vulnerability priority rating field' do
    before do
      allow(@content_service).to receive(:create_evidence) do |args|
        OpenStruct.new(args)
      end

      expect_any_instance_of(Dradis::Plugins::TemplateService)
      .to receive(:template_source).and_return("#[VPR]#\n%report_item.vpr_score%\n")
    end

    context '<vpr_score>' do
      it 'exports the vpr_score field' do
        expect(@content_service).to receive(:create_issue).with(hash_including text: "#[VPR]#\n9.0\n")
        @importer.import(file: 'spec/fixtures/files/vulnerability_priority_rating.xml')
      end
    end

    context '<vulnerability_priority_rating>' do
      it 'exports the vpr_score field' do
        expect(@content_service).to receive(:create_issue).with(hash_including text: "#[VPR]#\n9.0\n")
        @importer.import(file: 'spec/fixtures/files/vpr_score.xml')
      end
    end
  end
end
