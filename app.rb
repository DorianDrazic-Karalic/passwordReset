require 'sinatra'
require 'sqlite3'
require 'bcrypt'
require 'securerandom'
require 'cgi'
require 'time'

enable :sessions
set :session_secret, SecureRandom.hex(64)


DB = SQLite3::Database.new("users.db")
DB.results_as_hash = true


before do
  cache_control :no_store
end

helpers do
  def find_user(email)
    DB.get_first_row("SELECT * FROM users WHERE email = ?", [email])
  end

  def update_user(email, fields)
    set_clause = fields.keys.map { |k| "#{k} = ?" }.join(", ")
    values = fields.values + [email]
    DB.execute("UPDATE users SET #{set_clause} WHERE email = ?", values)
  end

  def current_user
    if session[:user_email]
      find_user(session[:user_email])
    else
      nil
    end
  end
end

get '/' do
  if current_user
    headers "Cache-Control" => "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma" => "no-cache",
            "Expires" => "Fri, 01 Jan 1990 00:00:00 GMT"
    erb :welcome
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
  user = find_user(email)

  if user && BCrypt::Password.new(user['password_hash']) == password
    session[:user_email] = email
    redirect '/'
  else
    @error = "Invalid email or password"
    erb :login
  end
end

get '/logout' do
  session.clear
  @notice = "You have been logged out."
  erb :login
end

get '/forgot' do
  erb :forgot
end

post '/forgot' do
  email = params[:email]
  @message = "If an account with that email exists, a reset link has been sent."
  @reset_link = nil

  user = find_user(email)

  if user
    token = SecureRandom.hex(20)
    update_user(email, {
      reset_token: token,
      reset_sent_at: Time.now.iso8601
    })
    @reset_link = "http://localhost:4567/reset?token=#{token}&email=#{CGI.escape(email)}"
    puts "Reset link: #{@reset_link}"
  end

  erb :forgot
end

get '/reset' do
  token = params[:token]
  email = params[:email]
  user = find_user(email)

  if user && user['reset_token'] == token
    sent_time = Time.parse(user['reset_sent_at']) rescue Time.at(0)
    if Time.now - sent_time > 1800
      update_user(email, reset_token: nil, reset_sent_at: nil)
      @error = "Reset link expired."
      erb :login
    else
      @token = token
      @email = email
      erb :reset
    end
  else
    @error = "Invalid or expired reset link."
    erb :login
  end
end

post '/reset' do
  email = params[:email]
  token = params[:token]
  new_password = params[:new_password]
  confirm_password = params[:confirm_password]
  user = find_user(email)

  if user.nil? || user['reset_token'] != token
    @error = "Invalid or expired reset token."
    return erb :login
  end

  if new_password.nil? || new_password.strip.empty?
    @error = "Password cannot be empty."
  elsif new_password != confirm_password
    @error = "Passwords do not match."
  elsif BCrypt::Password.new(user['password_hash']) == new_password
    @error = "New password cannot be the same as the current password."
  end

  if @error.nil?
    new_hash = BCrypt::Password.create(new_password)
    update_user(email, password_hash: new_hash, reset_token: nil, reset_sent_at: nil)
    @notice = "Password updated successfully."
    erb :login
  else
    @email = email
    @token = token
    erb :reset
  end
end
