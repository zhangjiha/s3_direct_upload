module S3DirectUpload
  module UploadHelper
    def s3_uploader_form(options = {}, &block)
      uploader = S3Uploader.new(options)
      content_tag(:div, uploader.wrapper_options) do
        uploader.fields.map do |name, value|
          hidden_field_tag(name, value)
        end.join.html_safe + capture(&block)
      end
    end

    alias_method :s3_uploader, :s3_uploader_form

    def s3_uploader_url ssl = true
      S3DirectUpload.config.url || "http#{ssl ? 's' : ''}://#{S3DirectUpload.config.region || "s3"}.amazonaws.com/#{S3DirectUpload.config.bucket}/"
    end

    class S3Uploader
      def initialize(options)
        @key_starts_with = options[:key_starts_with] || "uploads/"
        @options = options.reverse_merge(
          aws_access_key_id: S3DirectUpload.config.access_key_id,
          aws_secret_access_key: S3DirectUpload.config.secret_access_key,
          bucket: options[:bucket] || S3DirectUpload.config.bucket,
          ssl: true,
          acl: "private",
          region: S3DirectUpload.config.region || "us-east-1",
          url: S3DirectUpload.config.url,
          expiration: 10.hours.from_now.utc.iso8601,
          max_file_size: 500.megabytes,
          callback_method: "POST",
          callback_param: "file",
          server_side_encryption: nil,
          key_starts_with: @key_starts_with,
          key: key,
          date: Time.now.utc.strftime("%Y%m%d"),
          timestamp: Time.now.utc.strftime("%Y%m%dT%H%M%SZ")
        )
      end

      def wrapper_options
        {
          id: @options[:id],
          class: @options[:class],
          enforce_utf8: false,    #Rails的form_tag会自动加上 utf-8的hidden tag, 导致无法通过Amazon的'AWS4-HMAC-SHA256'认证
          data: {
            callback_url: @options[:callback_url],
            callback_method: @options[:callback_method],
            callback_param: @options[:callback_param]
          }.reverse_merge(@options[:data] || {})
        }
      end

      def fields
        {
          :key => @options[:key] || key,
          :acl => @options[:acl],
          :policy => policy,
          :success_action_status => "201",
          'X-Requested-With' => 'xhr',
          "x-amz-server-side-encryption" => @options[:server_side_encryption],
          'X-Amz-Algorithm' => 'AWS4-HMAC-SHA256',
          'X-Amz-Credential' => "#{@options[:aws_access_key_id]}/#{@options[:date]}/#{@options[:region]}/s3/aws4_request",
          'X-Amz-Date' => @options[:timestamp],
          'X-Amz-Signature' => signature
        }.delete_if { |k, v| v.nil? }
      end

      def key
        @key ||= "#{@key_starts_with}{timestamp}-{unique_id}/${filename}"
      end

      def policy
        Base64.encode64(policy_data.to_json).gsub("\n", "")
      end

      def policy_data
        {
          expiration: @options[:expiration],
          conditions: [
            ["starts-with", "$key", @options[:key_starts_with]],
            ["starts-with", "$x-requested-with", ""],
            ["content-length-range", 0, @options[:max_file_size]],
            ["starts-with","$content-type", @options[:content_type_starts_with] ||""],
            {bucket: @options[:bucket]},
            {acl: @options[:acl]},
            {success_action_status: "201"},
            {'X-Amz-Algorithm' => 'AWS4-HMAC-SHA256'},
            {'X-Amz-Credential' => "#{@options[:aws_access_key_id]}/#{@options[:date]}/#{@options[:region]}/s3/aws4_request"},
            {'X-Amz-Date' => @options[:timestamp]}
          ] + server_side_encryption + (@options[:conditions] || [])
        }
      end

      def server_side_encryption
        if @options[:server_side_encryption]
          [ { "x-amz-server-side-encryption" => @options[:server_side_encryption] } ]
        else
          []
        end
      end

      def signing_key
        #AWS Signature Version 4
        kDate    = OpenSSL::HMAC.digest('sha256', "AWS4" + @options[:aws_secret_access_key], @options[:date])
        kRegion  = OpenSSL::HMAC.digest('sha256', kDate, @options[:region])
        kService = OpenSSL::HMAC.digest('sha256', kRegion, 's3')
        kSigning = OpenSSL::HMAC.digest('sha256', kService, "aws4_request")

        kSigning
      end

      def signature
        OpenSSL::HMAC.hexdigest('sha256', signing_key, policy)
      end
    end
  end
end
