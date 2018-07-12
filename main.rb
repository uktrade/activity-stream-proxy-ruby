require 'sinatra'

configure do
  set :port, ENV['PORT']
end

get '/' do
  [200, {'Content-Type'=>'application/json'}, '{"content”:”for-pen-test"}']
end
