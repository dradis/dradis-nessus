module Dradis
  module Plugins
    module Nessus

      class FieldProcessor < Dradis::Plugins::Upload::FieldProcessor

        def post_initialize(args={})
          @nessus_object = (data.name == 'ReportHost') ? ::Nessus::Host.new(data) : ::Nessus::ReportItem.new(data)
        end

        def value(args={})
          field = args[:field]

          # fields in the template are of the form <foo>.<field>, where <foo>
          # is common across all fields for a given template (and meaningless).
          _, name = field.split('.')

          if name.end_with?('entries')
            # report_item.bid_entries
            # report_item.cve_entries
            # report_item.xref_entries
            entries = @nessus_object.try(name)
            if entries.any?
              entries.to_a.join("\n")
            else
              'n/a'
            end
          else
            output = @nessus_object.try(name) || 'n/a'

            if fields_with_lists.include?(field)
              format_bullet_point_lists(output)
            else
              output
            end
          end
        end

        private
        def fields_with_lists
          ['report_item.description', 'report_item.solution']
        end

        def format_bullet_point_lists(input)
          input.split("\n").map do |paragraph|
            if paragraph =~ /^  - (.*)$/m
              '* ' + $1.gsub(/    /, '').gsub(/\n/, ' ')
            elsif paragraph =~ /^- (.*)$/m
              '* ' + $1.gsub(/    /, '').gsub(/\n/, ' ')
            else
              paragraph
            end
          end.join("\n\n")
        end
      end

    end
  end
end