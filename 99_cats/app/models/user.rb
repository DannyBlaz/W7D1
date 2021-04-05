class User < ApplicationRecord
  
  before_validate :ensure_session_token
  validates :username, presence: true, unique: true
  validates :password_digest, presence: true
  validates :session_token, presence: true
  validates :password, length: { minimum: 6, allow_nil: true }

  def self.generate_session_token
    SecureRandom.urlsafe_base64(16)
  end

  def self.find_by_credentials(username, pw)
    # User.find_by(
    #   username: username,
    #   password_digest: BCrypt::Password.new(pw).to_s
    # )
    user = User.find_by(username: username)
    return user if user && BCrypt::Password.new(user.password_digest).is_password?(pw)
    nil
  end

  def ensure_session_token
    self.session_token ||= User.generate_session_token
  end

  def reset_session_token
    self.session_token = User.generate_session_token
    self.save!
    self.session_token
  end

  def password=(pw)
    password = pw
    self.password_digest = BCrypt::Password.create(pw)
  end


  private

  attr_reader :password

end
