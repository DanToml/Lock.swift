source 'https://rubygems.org'

gem 'fastlane', :github => 'fastlane/fastlane', :branch => 'dani_8.3.2'
gem 'cocoapods', '~> 1.0'
gem 'xcpretty-travis-formatter'
gem 'carthage_cache', '~> 0.5'
plugins_path = File.join(File.dirname(__FILE__), 'fastlane', 'Pluginfile')
eval(File.read(plugins_path), binding) if File.exist?(plugins_path)
