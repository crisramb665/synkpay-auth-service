/** npm imports */
import { Module } from '@nestjs/common'
import { ConfigModule, ConfigService } from '@nestjs/config'
import { JwtModule } from '@nestjs/jwt'
import { PassportModule } from '@nestjs/passport'
import { HttpModule } from '@nestjs/axios'

/** local imports */
import { AuthService } from './auth.service'
import { AuthController } from './auth.controller'
import { LoggerModule } from '../logging/logger.module'
import { ConfigKey } from '../config/enums'
import { RedisModule } from '../redis/redis.module'
import { SDKFinanceService } from '../sdk-finance/sdk-finance.service'

@Module({
  imports: [
    ConfigModule,
    PassportModule,
    LoggerModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        privateKey: configService.get<string>(ConfigKey.JWT_PRIVATE_KEY_DEV),
        signOptions: {
          algorithm: 'RS256',
          expiresIn: configService.get<string>(ConfigKey.JWT_EXPIRE_TIME), //! This is for accessToken only
        },
      }),
    }),
    HttpModule,
    RedisModule,
  ],
  controllers: [AuthController],
  providers: [AuthService, SDKFinanceService],
})
export class AuthModule {}
