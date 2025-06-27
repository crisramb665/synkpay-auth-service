/** npm imports */
import { Module } from '@nestjs/common'
import { ConfigModule } from '@nestjs/config'

/** local imports */
import { AppController } from './app.controller'
import config from './config/config'
import { LoggerService } from './logging/logger.service'
import { AuthModule } from './auth/auth.module'

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [config],
    }),
    AuthModule,
  ],
  controllers: [AppController],
  providers: [LoggerService],
  exports: [LoggerService],
})
export class AppModule {}
