# encoding: utf-8
require "logstash/outputs/base"
require "logstash/namespace"
require "base64"
require "digest"
require 'json'
require 'net/http'
require 'net/https'
require 'openssl'
require 'socket'
require 'time'
require 'uri'

# An example output that does nothing.
class LogStash::Outputs::Example < LogStash::Outputs::Base
  config_name "oms"

  # The OMS Customer ID to use
  config :workspaceID, :validate => :string, :required => :true

  # The OMS Shared Key to use
  config :sharedKey, :validate => :string, :required => :true

  # The OMS Log Type to use
  config :logType, :required => :true

  public
  def register
  end # def register

  public
  def receive(event)
    post_data(event)
    return "Event received"
  end # def event

    def build_signature(date, contentLength)
      method = 'POST'
      contentType = 'application/json'
      resource = '/api/logs'

      xHeaders = "x-ms-date:#{date}"
      stringToHash = "#{method}\n#{contentLength}\n#{contentType}\n#{xHeaders}\n#{resource}"

      key = Base64.decode64(sharedKey)
      hash = Base64.encode64(OpenSSL::HMAC.digest('sha256', key, stringToHash)).strip
      signature = "SharedKey #{workspaceID}:#{hash}"

      return signature
    end # build_signature 

    def post_data(records)
      msg = JSON.dump(records)

      date = Time.now.utc.httpdate()
      contentLength = msg.bytesize
      signature = build_signature(date, contentLength)

      headers = {}
      
      headers[CaseSensitiveString.new("Authorization")] = signature
      headers[CaseSensitiveString.new("Log-Type")] = logType
      headers[CaseSensitiveString.new("x-ms-date")] = date 
      headers["Content-Type"] = 'application/json'
      headers["Content-Length"] = contentLength.to_s

      req = Net::HTTP::Post.new("https://" + workspaceID + ".ods.opinsights.azure.com/api/logs?api-version=2016-04-01", headers)
      req.body = msg
 
	http = create_secure_http( URI.parse("https://" + workspaceID + ".ods.opinsights.azure.com/api/logs?api-version=2016-04-01") , "") 
      start_request(req, http)

      return contentLength
    end # post_data 

    def start_request(req, secure_http, ignore404 = false)
        # Tries to send the passed in request
        # Raises an exception if the request fails.
        # This exception should only be caught by the fluentd engine so that it retries sending this 
        begin
          res = nil
          res = secure_http.start { |http|  http.request(req) }
	rescue => e
		@logger.error("Error in section 1  #{e.message}")
        else
	  if res.nil?
		@logger.error("Failed to request method")
	  end

	  if res.is_a?(Net::HTTPSuccess)
            return res.body
          end

          if ignore404 and res.code == "404"
            return ''
          end

          if res.code != "200"
            # Retry all failure error codes...
            res_summary = "(class=#{res.class.name}; code=#{res.code}; message=#{res.message}; body=#{res.body};)"
            @logger.error("Failed #{res_summary}")
  
	end

        end # end begin
      end # end start_request

      # create an HTTP object which uses HTTPS
      def create_secure_http(uri, proxy={})
        if proxy.empty?
          http = Net::HTTP.new( uri.host, uri.port )
        else
          http = Net::HTTP.new( uri.host, uri.port,
                                proxy[:addr], proxy[:port], proxy[:user], proxy[:pass])
        end
        http.use_ssl = true
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE
        http.open_timeout = 30
        return http
      end # create_secure_http

end # class LogStash::Outputs::Example

class CaseSensitiveString < String
    def downcase
        self
    end
    def capitalize
        self
    end
end
