/** npm imports */
import { Injectable, OnModuleDestroy } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import Redis from 'ioredis'

/** local imports */
import { ConfigKey } from '../config/enums'

@Injectable()
export class RedisService implements OnModuleDestroy {
  private readonly redisClient: Redis

  constructor(private readonly configService: ConfigService) {
    this.redisClient = new Redis({
      host: this.configService.get<string>(ConfigKey.REDIS_HOST),
      port: this.configService.get<number>(ConfigKey.REDIS_PORT),
    })
  }

  async setValue(key: string, value: any, ttlMiliSeconds?: number): Promise<void> {
    let val: string
    if (typeof value === 'string') {
      try {
        JSON.parse(value)
        val = value
      } catch {
        val = JSON.stringify(value)
      }
    } else {
      val = JSON.stringify(value)
    }

    if (ttlMiliSeconds) await this.redisClient.set(key, val, 'PX', ttlMiliSeconds)
    else await this.redisClient.set(key, val)
  }

  async getValue(key: string): Promise<string | null> {
    const value = await this.redisClient.get(key)
    if (!value) return null

    return value
  }

  async deleteValue(key: string): Promise<void> {
    await this.redisClient.del(key)
  }

  async exist(key: string): Promise<boolean> {
    const result = await this.redisClient.exists(key)
    return result === 1
  }

  async onModuleDestroy(): Promise<void> {
    await this.redisClient.quit()
  }
}
