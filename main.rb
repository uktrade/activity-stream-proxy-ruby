require 'securerandom'
require 'sinatra'

class ExpiringSet
  def initialize(seconds)
    @seconds = seconds
    @expires = {}
  end

  def remove_old_keys(now)
     @expires = @expires.select { |item, expires| expires > now }
  end

  def add(item)
    now = Time.now.to_i
    remove_old_keys(now)
    item_expires = now + @seconds
    @expires[item] = item_expires unless @expires.key?(item)
  end

  def include?(item)
    now = Time.now.to_i
    self.remove_old_keys(now)
    @expires.key?(item)
  end
end

configure do
  set :port, ENV['PORT']

  set :authorized_ip_addresses, ENV['ACTIVITY_STREAM_IP_WHITELIST'].split(',')
  set :correct_username, ENV['KEY_ID']
  set :correct_password, ENV['SECRET_KEY']

  generated_nonce_expire = 15
  set :server_nonces_generated, ExpiringSet.new(generated_nonce_expire)

  used_nonce_expire = 60
  set :server_nonces_used, ExpiringSet.new(used_nonce_expire)
  set :client_nonces_used, ExpiringSet.new(used_nonce_expire)
  set :correct_realm, 'activity-stream-proxy'
  set :correct_qop, 'auth-int'
end

def secure_compare(a, b)
  return false if a.empty? || b.empty? || a.bytesize != b.bytesize

  l = a.unpack "C#{a.bytesize}"
  res = 0
  b.each_byte { |byte| res |= byte ^ l.shift }
  res == 0
end

get '/' do
  def respond_401()
    nonce = SecureRandom.hex(64)
    settings.server_nonces_generated.add(nonce)
    www_authenticate = "Digest realm=\"#{settings.correct_realm}\", " +
                       "qop=\"#{settings.correct_qop}\", algorithm=SHA-256, nonce=\"#{nonce}\""

    headers = {
      'Content-Type'=>'application/json',
      'WWW-Authenticate' => www_authenticate,
    }
    [401, headers, '{"details":"Unable to authenticate"}']
  end

  # IP address validation
  return respond_401 unless request.env.key?('HTTP_X_FORWARDED_FOR')
  remote_ips = request.env['HTTP_X_FORWARDED_FOR'].split(',')
  return respond_401 unless remote_ips.length >= 2 && settings.authorized_ip_addresses.include?(remote_ips[-2].strip)

  # Header structure check
  return respond_401 unless request.env.key?('HTTP_AUTHORIZATION')
  authorization_header = request.env['HTTP_AUTHORIZATION']
  parsed_header_array = authorization_header.scan(/([a-z]+)="([^"]+)"/)
  parsed_header = parsed_header_array.each_with_object({}) do |key_val, memo|
    memo[key_val[0].to_sym] = key_val[1]
  end
  return respond_401 unless parsed_header.key? :nonce
  return respond_401 unless parsed_header.key? :cnonce
  return respond_401 unless parsed_header.key? :username
  return respond_401 unless parsed_header.key? :response

  # Nonce check + store
  server_nonce_generated = settings.server_nonces_generated.include?(parsed_header[:nonce])
  server_nonce_available = not(settings.server_nonces_used.include?(parsed_header[:nonce]))
  client_nonce_available = not(settings.client_nonces_used.include?(parsed_header[:cnonce]))
  settings.server_nonces_used.add(parsed_header[:nonce])
  settings.client_nonces_used.add(parsed_header[:cnonce])
  return respond_401 unless server_nonce_generated and server_nonce_available and client_nonce_available

  # Username check
  return respond_401 unless secure_compare(parsed_header[:username], settings.correct_username)

  # Hash check
  hmac_payload_hash = Digest::SHA256.hexdigest(request.body.read)
  hmac_data_hash = Digest::SHA256.hexdigest(
      "#{request.request_method}:#{request.fullpath}:#{hmac_payload_hash}")
  hmac_secret_hash = Digest::SHA256.hexdigest(
      "#{settings.correct_username}:#{settings.correct_realm}:#{settings.correct_password}")
  nonce_c = '00000001'  # We only allow nonce to be used once
  hmac_value = Digest::SHA256.hexdigest(
      "#{hmac_secret_hash}:#{parsed_header[:nonce]}:" +
      "#{nonce_c}:#{parsed_header[:cnonce]}:#{settings.correct_qop}:" +
      "#{hmac_data_hash}"
    )
  return respond_401 unless secure_compare(parsed_header[:response], hmac_value)

  [200, {'Content-Type'=>'application/json'}, '{"content":"for-pen-test"}']
end
