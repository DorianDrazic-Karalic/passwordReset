require 'sinatra'
require 'bcrypt'
require 'securerandom'
require 'cgi'

enable :sessions
set :session_secret, SecureRandom.hex(64)

USERS = {
  "test@gmail.com" => {
    name: "test",
    password_hash: "$2a$12$x//L9tvIA82ECjTwTQ7PtuXcSWUJMuAo4BgYVB4Rk6MosvnQCu.YO",
    reset_token: nil
  }
}

helpers do
  def current_user
    if session[:user_email] && USERS.key?(session[:user_email])
      USERS[session[:user_email]]
    else
      nil
    end
  end
end

get '/' do
  if current_user
    "Welcome, #{current_user[:name]}! <a href='/logout'>Logout</a>"
  else
    redirect '/login'
  end
end

get '/login' do
  erb :login
end

post '/login' do
  email = params[:email]
  password = params[:password]
  user = USERS[email]

  if user && BCrypt::Password.new(user[:password_hash]) == password
    session[:user_email] = email
    redirect '/'
  else
    @error = "Invalid email or password"
    erb :login
  end
end

get '/logout' do
  session.clear
  redirect '/login'
end

get '/forgot' do
  erb :forgot
end

post '/forgot' do
  email = params[:email]
  @message = "If an account with that email exists, a reset link has been sent."

  if USERS.key?(email)
    puts "Email found: #{email}"
    token = SecureRandom.hex(20)
    USERS[email][:reset_token] = token
    puts "Reset link: http://localhost:4567/reset?token=#{token}&email=#{CGI.escape(email)}"
  else
    puts "Email not found: #{email}"
  end

  erb :forgot
end

get '/reset' do
  token = params[:token]
  email = params[:email]
  if email && token && USERS.key?(email) && USERS[email][:reset_token] == token
    @email = email  
    @token = token   
    erb :reset
  else
    "Invalid or expired password reset link."
  end
end

post '/reset' do
  email = params[:email]
  token = params[:token]
  new_password = params[:new_password]
  confirm_password = params[:confirm_password]

  if new_password.nil? || new_password.empty?
    @error = "Password cannot be empty."
  elsif new_password != confirm_password
    @error = "Passwords do not match."
  end

  user = USERS[email]

  if @error.nil? && user && token && user[:reset_token] == token
    if BCrypt::Password.new(user[:password_hash]) == new_password
      @error = "New password cannot be the same as the current password."
    end
  end

  if @error.nil? && user && token && user[:reset_token] == token
    user[:password_hash] = BCrypt::Password.create(new_password)
    user[:reset_token] = nil 
    @notice = "Password updated successfully. Please log in with your new password."
    return erb :login  
    @error ||= "Invalid token or email."
  end

  @email = email
  @token = token
  erb :reset
end

