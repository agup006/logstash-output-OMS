require "logstash/devutils/rspec/spec_helper"
require "logstash/outputs/oms"
require "thread"
require "sinatra"

PORT = rand(65535-1024) + 1025

class LogStash::Outputs::OMS
  attr_writer :agent
  attr_reader :request_tokens
end

# note that Sinatra startup and shutdown messages are directly logged to stderr so
# it is not really possible to disable them without reopening stderr which is not advisable.
#
# == Sinatra (v1.4.6) has taken the stage on 51572 for development with backup from WEBrick
# == Sinatra has ended his set (crowd applauds)

class TestApp < Sinatra::Base

  # disable WEBrick logging
  def self.server_settings
    { :AccessLog => [], :Logger => WEBrick::BasicLog::new(nil, WEBrick::BasicLog::FATAL) }
  end

  def self.multiroute(methods, path, &block)
    methods.each do |method|
      method.to_sym
      self.send method, path, &block
    end
  end

  def self.last_request=(request)
    @last_request = request
  end

  def self.last_request
    @last_request
  end
end

RSpec.configure do |config|
  #http://stackoverflow.com/questions/6557079/start-and-call-ruby-http-server-in-the-same-script
  def sinatra_run_wait(app, opts)
    queue = Queue.new

    Thread.new(queue) do |queue|
      begin
        app.run!(opts) do |server|
          queue.push("started")
        end
      rescue
        # ignore
      end
    end

    queue.pop # blocks until the run! callback runs
  end

  config.before(:suite) do
    sinatra_run_wait(TestApp, :port => PORT, :server => 'webrick')
  end
end

describe LogStash::Outputs::OMS do
  # Wait for the async request to finish in this spinlock
  # Requires pool_max to be 1
  def wait_for_request

    loop do
      sleep(0.1)
      break if subject.request_tokens.size > 0
    end
  end

  let(:workspace_id) { "---- WORKSPACE ID ----" }
  let(:shared_key) { "---- SHARED KEY ----" }
  let(:log_type) { "---- LOG TYPE ----" }
 
  let(:event) { LogStash::Event.new("message" => "hi") }
  let(:method) { "post" }


  describe "when num requests > token count" do
    let(:pool_max) { 10 }
    let(:num_reqs) { pool_max / 2 }
    let(:client) { subject.client }
    let(:client_proxy) { subject.client.background }

    subject {
      LogStash::Outputs::OMS.new("workspace_id" => workspace_id,
                                      "shared_key" => shared_key,
                                      "log_type" => log_type)
    }

    before do
      allow(client).to receive(:background).and_return(client_proxy)
      subject.register
    end

    after do
      subject.close
    end

    it "should receive all the requests" do
      expect(client_proxy).to receive(:send).
                          with(method.to_sym, "https://" + workspace_id + ".ods.opinsights.azure.com/api/logs?api-version=2016-04-01", anything).
                          exactly(num_reqs).times.
                          and_call_original

      num_reqs.times {|t| subject.receive(event)}
    end
  end
end