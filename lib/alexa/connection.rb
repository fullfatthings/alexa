require "cgi"
require "base64"
require "openssl"
require "digest/sha1"
require "faraday"
require "time"

module Alexa
  class Connection
    attr_accessor :secret_access_key, :access_key_id
    attr_writer :params

    RFC_3986_UNRESERVED_CHARS = "-_.~a-zA-Z\\d"
    SIGNATURE_ALGORITHM = 'AWS4-HMAC-SHA256'

    def initialize(credentials = {})
      self.secret_access_key = credentials.fetch(:secret_access_key)
      self.access_key_id     = credentials.fetch(:access_key_id)
    end

    def params
      @params ||= {}
    end

    def get(params = {})
      self.params = params
      handle_response(request).body.force_encoding(Encoding::UTF_8)
    end

    private

    def handle_response(response)
      case response.status.to_i
      when 200...300
        response
      when 300...600
        raise ResponseError.new('Alexa API Error', response)
      else
        raise ResponseError.new("Unknown code: #{response.code}", response)
      end
    end

    def request
      Faraday.get(uri) do |req|
        req.headers = headers
      end
    end

    def timestamp
      @timestamp ||= Time::now.utc.strftime("%Y%m%dT%H%M%SZ")
    end

    def datestamp
      @datestamp ||= Time::now.utc.strftime("%Y%m%d")
    end

    def uri
      URI.parse("https://#{Alexa::API_HOST}#{Alexa::API_URI}?" + query)
    end

    def query
      params.map do |key, value|
        "#{key}=#{rfc3986_escape(value.to_s)}"
      end.sort.join('&')
    end

    def canonical_request
      headers_str = signed_headers.map { |k,v| k + ':' + v }.join("\n") + "\n"
      headers_lst = signed_headers.keys.join(';')
      'GET' + "\n" + Alexa::API_URI + "\n" + query + "\n" + headers_str + "\n" + headers_lst + "\n" + Digest::SHA256.hexdigest('')
    end

    def signed_headers
      {
        "host"       => Alexa::API_ENDPOINT,
        "x-amz-date" => timestamp
      }
    end

    def headers
      {
        "accept"        => "application/xml",
        "authorization" => authorization_header,
        "x-amz-date"    => timestamp
      }
    end

    def credentials_scope
      datestamp + "/" + Alexa::API_REGION + "/" + Alexa::API_NAME + "/" + "aws4_request"
    end

    def authorization_header
      headers_lst = signed_headers.keys.join(';')
      SIGNATURE_ALGORITHM + " " + "Credential=" + access_key_id + "/" + credentials_scope + ", " +  "SignedHeaders=" + headers_lst + ", " + "Signature=" + signature
    end

    def string_to_sign
      SIGNATURE_ALGORITHM + "\n" +  timestamp + "\n" +  credentials_scope + "\n" + (Digest::SHA256.hexdigest canonical_request)
    end

    def signature
      OpenSSL::HMAC.hexdigest('sha256', signature_key, string_to_sign)
    end

    def signature_key
      sig_date    = OpenSSL::HMAC.digest('sha256', 'AWS4' + secret_access_key, datestamp)
      sig_region  = OpenSSL::HMAC.digest('sha256', sig_date, Alexa::API_REGION)
      sig_service = OpenSSL::HMAC.digest('sha256', sig_region, Alexa::API_NAME)
      OpenSSL::HMAC.digest('sha256', sig_service, 'aws4_request')
    end

    def rfc3986_escape(str)
      URI.escape(str, Regexp.new("[^#{RFC_3986_UNRESERVED_CHARS}]"))
    end
  end
end
