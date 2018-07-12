require 'sinatra'

configure do
  set :port, ENV['PORT']
end

get '/' do
  "Hello World!"
end
