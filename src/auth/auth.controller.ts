/** npm imports */
import { Body, Controller, Get, Post, Query, Req, Res } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { Request, Response } from 'express'

/** local imports */
import { LoginDto } from './dtos/login.dto'
import { AuthService } from './auth.service'
import { LoggerService } from '../logging/logger.service'
import { parseExpirationTime } from './utils/utils'
import { ConfigKey } from '../config/enums'
import { RefreshTokenDto } from './dtos/refresh-token.dto'
import { LogoutDto } from './dtos/logout.dto'

@Controller('v1')
export class AuthController {
  constructor(
    private readonly configService: ConfigService,
    private readonly authService: AuthService,
    private readonly logger: LoggerService,
  ) {}

  @Post('login')
  public async login(@Body() body: LoginDto, @Res() res: Response) {
    const { login, password } = body

    try {
      const result = await this.authService.getTokens(login, password)
      const { status, apiGatewayAccessToken, apiGatewayRefreshToken, expiresAt } = result

      res.cookie('refreshToken', apiGatewayRefreshToken, {
        httpOnly: this.configService.get<string>(ConfigKey.NODE_ENV) === 'production',
        secure: this.configService.get<string>(ConfigKey.NODE_ENV) === 'production',
        sameSite: 'none',
        maxAge: parseExpirationTime(this.configService.get<string>(ConfigKey.JWT_REFRESH_EXPIRE_TIME) ?? '24h'),
      })

      return res.status(status).json({
        accessToken: apiGatewayAccessToken,
        refreshToken: apiGatewayRefreshToken,
        expiresAt: expiresAt,
      })
    } catch (error) {
      const statusCode = error.status || 401
      this.logger.error(`Login failed for user ${login} and status ${statusCode}`, error)

      return res.status(statusCode).json({
        message: error.message || 'Login failed',
        error: !!error,
      })
    }
  }

  @Post('refresh-token')
  public async refreshToken(@Body() body: RefreshTokenDto, @Req() req: Request, @Res() res: Response) {
    try {
      const refreshToken = body.refreshToken || req.cookies.refreshToken
      if (!refreshToken) {
        this.logger.error('Refresh token is missing in the request')
        return res.status(401).json({
          message: 'Refresh token is required',
          error: true,
        })
      }

      const result = await this.authService.refreshToken(refreshToken)
      const { status, apiGatewayAccessToken, apiGatewayRefreshToken, expiresAt } = result

      res.cookie('refreshToken', apiGatewayRefreshToken, {
        httpOnly: this.configService.get<string>(ConfigKey.NODE_ENV) === 'production',
        secure: this.configService.get<string>(ConfigKey.NODE_ENV) === 'production',
        sameSite: 'none',
        maxAge: parseExpirationTime(this.configService.get<string>(ConfigKey.JWT_REFRESH_EXPIRE_TIME) ?? '24h'),
      })

      return res.status(status).json({
        accessToken: apiGatewayAccessToken,
        refreshToken: apiGatewayRefreshToken,
        expiresAt: expiresAt,
      })
    } catch (error) {
      const statusCode = error.status || 401
      this.logger.error(`Refresh token attempt faile, status ${statusCode}`, error)

      return res.status(statusCode).json({
        message: error.message || 'Refresh token attempt failed',
        error: !!error,
      })
    }
  }

  @Post('logout')
  public async logout(@Body() body: LogoutDto, @Res() res: Response) {
    const userId = body.userId
    const response = await this.authService.revokeTokens(userId)
    const { status, revoked } = response

    if (!revoked) {
      this.logger.error(`Failed to revoke tokens for user ${userId}`)
      return res.status(status).json({
        message: 'Failed to revoke tokens',
        error: true,
      })
    }

    res.clearCookie('refreshToken', {
      httpOnly: this.configService.get<string>(ConfigKey.NODE_ENV) === 'production',
      secure: this.configService.get<string>(ConfigKey.NODE_ENV) === 'production',
      sameSite: 'none',
    })

    return res.status(status).json({ success: revoked })
  }

  // TODO: Remove this later
  @Get('sdk-tokens')
  public async getSdkFinanceTokensPerUser(@Query('userId') userId: string, @Res() res: Response) {
    const response = await this.authService.getSdkFinanceTokens(userId)

    const { sdkFinanceAccessToken, sdkFinanceRefreshToken } = response

    return res.status(200).json({ sdkFinanceAccessToken, sdkFinanceRefreshToken })
  }
}
