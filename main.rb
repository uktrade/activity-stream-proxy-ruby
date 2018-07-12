require 'sinatra'

configure do
  set :port, ENV['PORT']
end

get '/' do
  [200, {}, "Hello World!"]
end
