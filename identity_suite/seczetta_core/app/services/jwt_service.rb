class Services::JwtService

  def refresh_from_token(refresh_token)
    if (refresh_token = JwtRefreshToken.where(user_id: @user_id))
      refresh_token.destroy
    else
      raise JWTAlreadyRefreshedError
    end
    self.class.set_cookies(session: @session, cookies: @cookies)
    JwtRefreshToken.create!(user_id: @user_id, refresh_token: refresh_token)
  end

  def spawn_store(rotate_keys: false)
    store = SzAuth::Services::JwtService.spawn(logger: Rails.logger, token_type: token_type)
    if store
      current.jwt_store = store
      @store = current.jwt_store
    else
      Rails.logger.error("[SeczettaCore::JwtService] error: store not spawned")
  end

  def refresh
    decoded_token = handle_token(token: cookies['api_jwt_refresh'])
    @session[:user_id] = decoded_token['user_id']
    if (refresh_token = JwtRefreshToken.where(user_id: decoded_token[:user_id])).first
      refresh_token.destroy
    end
    if self.class.set_cookes(session: @session, cookies: @cookies)
      JwtRefreshToken.create!(user_id: @current_user, refresh_token: refresh_token)
    else
      # Three log errors have been written if call stack repeatadely reaches this.
      # this includes two errors from SeczettaCore and at least one from JwtService.
      nil
    end
  rescue => e
    Rails.logger.error{"[SeczettaCore::JwtService] error: #{e.message} while refreshing tokens"}
  end
  def token_output_method
    SeczettaCore::TenantFeatureFlag[:be_jwe_token].enabled? ? :decode : :decrypt
  end

  def token_input_method
    SeczettaCore::TenantFeatureFlag[:be_jwe_token].enabled? ? :encrypt : :encode
  end

  def decode_token(toke:, key:)
    JWT.decode(token, key, true, jwks: JWT::JWK::Set.new(jwk))
  end

  def decrypt_token(token:, key:)
    raise ArgumentError, "key invalid" unless jwk = jwk(key).to_json
    JSON.parse(JWE.decrypt(token, jwk.signing_key))
  end

  def jwt_binding_structure
    ["JwtBinding", :jwt_store]
  end

  def ses_binding_structure
    ["SessionBinding", :user, :tenant, :cookies]
  end
end
