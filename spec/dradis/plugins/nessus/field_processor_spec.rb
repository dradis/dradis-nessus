require 'spec_helper'
require 'ostruct'

describe Dradis::Plugins::Nessus::FieldProcessor do

  describe "%report_item.description% field formatting" do
    context "bullet points" do
      it "converts Nessus broken lists into Textile bullet-point lists" do
        doc = Nokogiri::XML(File.read('spec/fixtures/files/report_item-with-list.xml'))
        processor = described_class.new(data: doc.root)

        value = processor.value(field: 'report_item.description')
        expect(value).to_not be_empty

        expect(value).to include("* A denial of service vulnerability exists relating to the 'mod_dav' module as it relates to MERGE requests.\n\n    (CVE-2013-1896)")
      end
    end
  end

  it "Recasted severity values appear in the Evidence" do
    doc = Nokogiri::XML(File.read('spec/fixtures/files/report_item-with-list.xml'))
    processor = described_class.new(data: doc.root)
    value = processor.value(field: 'evidence.severity')
    expect(value).to_not be_empty
    expect(value).to include("2")
  end
end
