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
    @set.include(item)
  end
end

nonce_expire = 15
$server_nonces_generated = ExpiringSet.new(nonce_expire)
$server_nonces_used = ExpiringSet.new(nonce_expire)
$client_nonces_used = ExpiringSet.new(nonce_expire)
$correct_realm = 'activity-stream-proxy-ruby'
$correct_qop = 'auth'

def respond_401()
  nonce = SecureRandom.hex(64)
  $server_nonces_generated.add(nonce)
  www_authenticate = "Digest realm=\"#{$correct_realm}\", qop=\"#{$correct_qop}\", algorithm=SHA-256, nonce=\"#{nonce}\""

  headers = {
    'Content-Type'=>'application/json',
    'WWW-Authenticate' => www_authenticate,
  }
  [401, headers, '{"details":"Unable to authenticate"}']
end

authorized_ip_addresses = ENV['ACTIVITY_STREAM_IP_WHITELIST'].split(',')

get '/' do
  # IP address validation
  return respond_401 unless request.env.key?('HTTP_X_FORWARDED_FOR')
  remote_ips = request.env['HTTP_X_FORWARDED_FOR'].split(',')
  return response_401 unless remote_ips.length >= 2 && authorized_ip_addresses.include?(remote_ips[-2])

  [200, {'Content-Type'=>'application/json'}, '{"content":"for-pen-test"}']
end
