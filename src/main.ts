/** npm imports */
import { NestFactory } from '@nestjs/core'
import { ConfigService } from '@nestjs/config'

/** local imports */
import { AppModule } from './app.module'
import { LoggerService } from './logging/logger.service'
import { ConfigKey } from './config/enums'

async function bootstrap() {
  try {
    const app = await NestFactory.create(AppModule)

    const configService = app.get(ConfigService)
    const logger = new LoggerService(configService)

    const port = configService.get<number>(ConfigKey.PORT) || 4000

    await app.listen(port)

    logger.log(`🚀🚀🚀 Synk Pay Auth service is running on: http://localhost:${port}/`)
  } catch (error) {
    if (error instanceof Error) console.error('Error during bootstrap:', error.message)
    else console.error('Error during bootstrap:', error)

    process.exit(1)
  }
}
void bootstrap()
