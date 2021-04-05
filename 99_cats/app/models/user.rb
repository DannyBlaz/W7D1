class User < ApplicationRecord
  
  before_validation :ensure_session_token
  validates :username, presence: true, uniqueness: true
  validates :password_digest, presence: true
  validates :session_token, presence: true
  validates :password, length: { minimum: 6, allow_nil: true }

  def self.generate_session_token
    SecureRandom.urlsafe_base64(16)
  end

  def self.find_by_credentials(username, pw)
    # User.find_by(
    #   username: username,
    #   password_digest: BCrypt::Password.create(pw).to_s  # this doesn't work because it adds a new salt every time
    # )
    user = User.find_by(username: username) # this works because it adds the salt from the DB to pw to check if the hashes are equal
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
