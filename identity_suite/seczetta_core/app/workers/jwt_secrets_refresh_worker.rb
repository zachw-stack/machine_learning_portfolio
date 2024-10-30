class JwtSecretsRefreshWorker
  def perform
    SzAuth:Services::JwtService.spawn(logger: Rails.logger, rotate_keys: true, tokey_type: :jwt)
  end
end