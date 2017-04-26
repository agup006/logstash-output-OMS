# encoding: utf-8
require "logstash/outputs/base"
require "logstash/namespace"
require "logstash/json"
require "uri"
require "logstash/plugin_mixins/http_client"

class LogStash::Outputs::OMS < LogStash::Outputs::Base
  include LogStash::PluginMixins::HttpClient

  # This output lets you send events to an OMS workspace via HTTP(S)
  #
  # This output will execute up to 'pool_max' requests in parallel for performance.
  # Consider this when tuning this plugin for performance.
  #
  # Additionally, note that when parallel execution is used strict ordering of events is not
  # guaranteed!
  #
  # Beware, this gem does not yet support codecs. Please use the 'format' option for now.

  config_name "oms"

  # Content type
  #
  # If not specified, this defaults to the following:
  #
  # * if format is "json", "application/json"
  # * if format is "form", "application/x-www-form-urlencoded"
  config :content_type, :validate => :string

  # This lets you choose the structure and parts of the event that are sent.
  #
  #
  # For example:
  # [source,ruby]
  #    mapping => {"foo", "%{host}", "bar", "%{type}"}
  config :mapping, :validate => :hash

  # Set the format of the http body.
  #
  # If form, then the body will be the mapping (or whole event) converted
  # into a query parameter string, e.g. `foo=bar&baz=fizz...`
  #
  # If message, then the body will be the result of formatting the event according to message
  #
  # Otherwise, the event is sent as json.
  config :format, :validate => ["json", "form", "message"], :default => "json"

  config :message, :validate => :string

  # The OMS Customer ID to use
  config :workspace_id, :validate => :string, :required => :true

  # The OMS Shared Key to use
  config :shared_key, :validate => :string

  # OMS credentials file
  config :oms_creds_file, :validate => :string

  # The OMS Log Type to use
  config :log_type, :required => :true

  def register
    @http_method = "post".to_sym

    # We count outstanding requests with this queue
    # This queue tracks the requests to create backpressure
    # When this queue is empty no new requests may be sent,
    # tokens must be added back by the client on success
    @request_tokens = SizedQueue.new(@pool_max)
    @pool_max.times {|t| @request_tokens << true }

    @requests = Array.new

    if @content_type.nil?
      case @format
        when "form" ; @content_type = "application/x-www-form-urlencoded"
        when "json" ; @content_type = "application/json"
        when "message" ; @content_type = "text/plain"
      end
    end

    if (@oms_creds_file and @shared_key)
      raise(LogStash::ConfigurationError, "Only one of :shared_key, :oms_creds_file may be set at a time.")
    end

    @shared_key = File.read(@oms_creds_file).strip if @oms_creds_file

    validate_format!
  end # def register

  def multi_receive(events)
    events.each {|event| receive(event, :parallel)}
    client.execute!
  end

  # Once we no longer need to support Logstash < 2.2 (pre-ng-pipeline)
  # We don't need to handle :background style requests
  #
  # We use :background style requests for Logstash < 2.2 because before the microbatching
  # pipeline performance is greatly improved by having some degree of async behavior.
  #
  # In Logstash 2.2 and after things are much simpler, we just run each batch in parallel
  # This will make performance much easier to reason about, and more importantly let us guarantee
  # that if `multi_receive` returns all items have been sent.
  def receive(event, async_type=:background)
    body = event_body(event)

    # Block waiting for a token
    token = @request_tokens.pop if async_type == :background

    # Send the request
    url = "https://" + workspace_id + ".ods.opinsights.azure.com/api/logs?api-version=2016-04-01" 
    headers = generate_headers(event)

    # Create an async request
    request = client.send(async_type).send(@http_method, url, :body => body, :headers => headers)

    request.on_complete do
      # Make sure we return the token to the pool
      @request_tokens << token  if async_type == :background
    end

    request.on_success do |response|
      if response.code < 200 || response.code > 299
        log_failure(
          "Encountered non-200 HTTP code #{200}",
          :response_code => response.code,
          :url => url,
          :event => event)
      end
    end

    request.on_failure do |exception|
      log_failure("Could not fetch URL",
                  :url => url,
                  :method => @http_method,
                  :body => body,
                  :headers => headers,
                  :message => exception.message,
                  :class => exception.class.name,
                  :backtrace => exception.backtrace
      )
    end

    request.call if async_type == :background
  end

  def close
    client.close
  end

  private

  # This is split into a separate method mostly to help testing
  def log_failure(message, opts)
    @logger.error("[OMS Output Failure] #{message}", opts)
  end

  # Manticore doesn't provide a way to attach handlers to background or async requests well
  # It wants you to use futures. The #async method kinda works but expects single thread batches
  # and background only returns futures.
  # Proposed fix to manticore here: https://github.com/cheald/manticore/issues/32
  def request_async_background(request)
    @method ||= client.executor.java_method(:submit, [java.util.concurrent.Callable.java_class])
    @method.call(request)
  end

  # Format the HTTP body
  def event_body(event)
    # TODO: Create an HTTP post data codec, use that here
    if @format == "json"
      LogStash::Json.dump(map_event(event))
    elsif @format == "message"
      event.sprintf(@message)
    else
      encode(map_event(event))
    end
  end

  def map_event(event)
    if @mapping
      @mapping.reduce({}) do |acc,kv|
        k,v = kv
        acc[k] = event.sprintf(v)
        acc
      end
    else
      event.to_hash
    end
  end

  def generate_headers(event)
    msg = LogStash::Json.dump(event)

    date = Time.now.utc.httpdate()
    contentLength = msg.bytesize
    signature = build_signature(date, contentLength)

    headers = {}

    headers[CaseSensitiveString.new("Authorization")] = signature
    headers[CaseSensitiveString.new("Log-Type")] = log_type
    headers[CaseSensitiveString.new("x-ms-date")] = date
    headers["Content-Type"] = 'application/json'
    return headers
  end

  def build_signature(date, contentLength)
    method = 'POST'
    contentType = 'application/json'
    resource = '/api/logs'

    xHeaders = "x-ms-date:#{date}"
    stringToHash = "#{method}\n#{contentLength}\n#{contentType}\n#{xHeaders}\n#{resource}"

    key = Base64.decode64(shared_key)
    hash = Base64.encode64(OpenSSL::HMAC.digest('sha256', key, stringToHash)).strip
    signature = "SharedKey #{workspace_id}:#{hash}"

    return signature
  end # build_signature

  #TODO Extract this to a codec
  def encode(hash)
    return hash.collect do |key, value|
      CGI.escape(key) + "=" + CGI.escape(value.to_s)
    end.join("&")
  end


  def validate_format!
    if @format == "message"
      if @message.nil?
        raise "message must be set if message format is used"
      end

      if @content_type.nil?
        raise "content_type must be set if message format is used"
      end

      unless @mapping.nil?
        @logger.warn "mapping is not supported and will be ignored if message format is used"
      end
    end
  end
end # class LogStash::Outputs::OMS

class CaseSensitiveString < String
    def downcase
        self
    end
    def capitalize
        self
    end
end