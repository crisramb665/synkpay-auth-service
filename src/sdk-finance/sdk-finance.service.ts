/** npm imports */
import { HttpService } from '@nestjs/axios'
import { ConfigService } from '@nestjs/config'
import { Injectable } from '@nestjs/common'
import { firstValueFrom } from 'rxjs'
import { AxiosRequestConfig, AxiosResponse } from 'axios'

/** local imports */
import { type MakeRequestParams, type AuthResponseWithStatus } from './sdk-finance.interface'

import { ConfigKey } from '../config/enums'
import { LoggerService } from '../logging/logger.service'

@Injectable()
export class SDKFinanceService {
  private readonly baseUrl: string | undefined

  constructor(
    private readonly configService: ConfigService,
    private readonly httpService: HttpService,
    private readonly logger: LoggerService,
  ) {
    this.baseUrl = this.configService.get<string>(ConfigKey.SDK_FINANCE_BASE_URL)
    if (!this.baseUrl) throw new Error('Missing SDK Finance base URL in environment configuration.')
  }

  public withToken(accessToken: string): AuthenticatedSDKFinanceClient {
    return new AuthenticatedSDKFinanceClient(this, accessToken)
  }

  public async makeRequest<T>({
    method,
    endpoint,
    data,
    headers,
  }: MakeRequestParams): Promise<{ status: number; data: T }> {
    try {
      const config: AxiosRequestConfig = {
        method,
        url: `${this.baseUrl}${endpoint}`,
        data,
        ...(headers ? { headers } : {}),
      }

      const response: AxiosResponse = await firstValueFrom(this.httpService.request(config))

      const { status, data: responseData } = response
      return { status, data: responseData as T }
    } catch (error: any) {
      const status = error?.response?.status || 500

      this.logger.error(`SDK Finance request failed: ${error?.message || 'Unknown error'}`, error.stack, {
        statusCode: status,
        endpoint,
        method,
        type: 'request',
      })

      throw new Error(error?.response?.data?.message || 'SDK Finance request failed', status)
    }
  }

  async authenticateUser(login: string, password: string): Promise<AuthResponseWithStatus> {
    return this.makeRequest({
      method: 'post',
      endpoint: '/v1/authorization',
      data: { login, password },
    })
  }

  async refreshToken(sdkFinanceRefreshToken: string): Promise<AuthResponseWithStatus> {
    return this.makeRequest({
      method: 'put',
      endpoint: '/v1/authorization',
      data: { refreshToken: sdkFinanceRefreshToken },
    })
  }
}

export class AuthenticatedSDKFinanceClient {
  constructor(
    private readonly sdkFinanceService: SDKFinanceService,
    private readonly sdkFinanceAccessToken: string,
  ) {}

  async deleteAccessTokenAndLogout(): Promise<{ status: number; data: unknown }> {
    return this.sdkFinanceService.makeRequest({
      method: 'delete',
      endpoint: '/v1/authorization',
      data: {},
      headers: {
        Authorization: `Bearer ${this.sdkFinanceAccessToken}`,
      },
    })
  }
}
