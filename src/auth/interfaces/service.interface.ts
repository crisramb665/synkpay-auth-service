export interface SessionValue {
  sdkFinanceToken: string
  sdkFinanceTokenExpiresAt: string
  jwtHash: string
}

export interface RefreshValue {
  sdkFinanceRefreshToken: string
  sdkFinanceRefreshTokenExpiresAt: string
  jwtRefreshHash: string
  jwtRefreshJtiHash: string
}
