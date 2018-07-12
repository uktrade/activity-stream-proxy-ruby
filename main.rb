require 'sinatra'

configure do
  set :port, ENV['PORT']
end

def respond_401()
  headers = {
    'Content-Type'=>'application/json',
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
