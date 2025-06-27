/** npm imports */
import { Module } from '@nestjs/common'

/** local imports */
import { RedisService } from './redis.service'

@Module({
  providers: [RedisService],
  exports: [RedisService],
})
export class RedisModule {}
