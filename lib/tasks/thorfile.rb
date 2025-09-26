class NessusTasks < Thor
  include Rails.application.config.dradis.thor_helper_module

  namespace "dradis:plugins:nessus"

  desc "upload FILE", "upload Nessus v2 results (.nessus file)"
  def upload(file_path)
    require 'config/environment'

    unless File.exist?(file_path)
      $stderr.puts "** the file [#{file_path}] does not exist"
      exit(-1)
    end

    detect_and_set_project_scope

    importer = Dradis::Plugins::Nessus::Importer.new(task_options)
    importer.import(file: file_path)
  end

end
