/** npm imports */
import { Module } from '@nestjs/common'
import { ConfigModule } from '@nestjs/config'

/** local imports */
import { LoggerService } from './logger.service'

@Module({
  imports: [ConfigModule],
  providers: [LoggerService],
  exports: [LoggerService],
})
export class LoggerModule {}
