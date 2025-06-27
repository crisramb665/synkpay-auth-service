/** npm imports */
import { IncomingMessage } from 'http'

export interface JwtPayload {
  sub: string
  name: string
  profileOrganizationId: string
  jti?: string //! Can be scalable for multiple auth types (using isolated service), but not required for now
}

export interface ContextReq extends IncomingMessage {
  user: JwtPayload
}
export interface LoginResponse {
  status: number
  apiGatewayAccessToken: string
  apiGatewayRefreshToken: string
  expiresAt: string
}

export type RefreshTokenResponse = LoginResponse
