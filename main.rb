require 'securerandom'
require 'sinatra'

configure do
  set :port, ENV['PORT']
end

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
    @expires[item] = item_expires
  end

  def include?(item)
    now = Time.now.to_i
    self.remove_old_keys(now)
    @expires.key?(item)
  end
end

generated_nonce_expire = 15
$server_nonces_generated = ExpiringSet.new(generated_nonce_expire)

client_nonce_expire = 60
$server_nonces_used = ExpiringSet.new(client_nonce_expire)
$client_nonces_used = ExpiringSet.new(client_nonce_expire)
$correct_realm = 'activity-stream-proxy-ruby'
$correct_qop = 'auth'

def respond_401()
  nonce = SecureRandom.hex(64)
  $server_nonces_generated.add(nonce)
  www_authenticate = "Digest realm=\"#{$correct_realm}\", " +
                     "qop=\"#{$correct_qop}\", algorithm=SHA-256, nonce=\"#{nonce}\""

  headers = {
    'Content-Type'=>'application/json',
    'WWW-Authenticate' => www_authenticate,
  }
  [401, headers, '{"details":"Unable to authenticate"}']
end

$authorized_ip_addresses = ENV['ACTIVITY_STREAM_IP_WHITELIST'].split(',')
$correct_username = ENV['KEY_ID']
$correct_password = ENV['SECRET_KEY']

def secure_compare(a, b)
  return false if a.empty? || b.empty? || a.bytesize != b.bytesize

  l = a.unpack "C#{a.bytesize}"
  res = 0
  b.each_byte { |byte| res |= byte ^ l.shift }
  res == 0
end

get '/' do
  # IP address validation
  return respond_401 unless request.env.key?('HTTP_X_FORWARDED_FOR')

  remote_ips = request.env['HTTP_X_FORWARDED_FOR'].split(',')
  return respond_401 unless remote_ips.length >= 2 && $authorized_ip_addresses.include?(remote_ips[-2].strip)
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
  return respond_401 unless secure_compare(parsed_header[:username], $correct_username)
  return respond_401 unless $server_nonces_generated.include?(parsed_header[:nonce])
  return respond_401 if $server_nonces_used.include?(parsed_header[:nonce]) 
  return respond_401 if $client_nonces_used.include?(parsed_header[:cnonce]) 

  hmac_data_hash = Digest::SHA256.hexdigest(
      "#{request.request_method}:#{request.fullpath}")
  hmac_secret_hash = Digest::SHA256.hexdigest(
      "#{$correct_username}:#{$correct_realm}:#{$correct_password}")

  nonce_c = '00000001'  # We only allow cnonce to be used once
  hmac_value = Digest::SHA256.hexdigest(
      "#{hmac_secret_hash}:#{parsed_header[:nonce]}:" +
      "#{nonce_c}:#{parsed_header[:cnonce]}:#{$correct_qop}:" +
      "#{hmac_data_hash}"
    )

  return respond_401 unless secure_compare(parsed_header[:response], hmac_value)

  $server_nonces_used.add(parsed_header[:nonce])
  $client_nonces_used.add(parsed_header[:cnonce])

  [200, {'Content-Type'=>'application/json'}, '{"content":"for-pen-test"}']
end
