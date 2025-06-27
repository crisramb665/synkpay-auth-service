/** npm imports */
import { createHash } from 'crypto'

export const hashJwt = (jwt: string): string => createHash('sha256').update(jwt).digest('hex')

export const parseExpirationTime = (expirationTime: string): number => parseInt(expirationTime.replace(/\D/g, ''))
