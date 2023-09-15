import {
    Injectable,
    OnApplicationBootstrap,
    OnApplicationShutdown,
  } from '@nestjs/common';
import Redis from 'ioredis';
import { ConfigService } from '@nestjs/config';
import { SignInDto } from './sign-in.dto';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from '../users/users.service';

export class InvalidatedRefreshTokenError extends Error {}

@Injectable()
export class RefreshTokenIdsStorage
  implements OnApplicationBootstrap, OnApplicationShutdown
{
  private redisClient: Redis;
  constructor(private configService: ConfigService) {}
  onApplicationBootstrap() {
    this.redisClient = new Redis({
      host: this.configService.get('REDIS_HOST'),
      port: this.configService.get('REDIS_PORT'),
    });
  }

  onApplicationShutdown(signal?: string) {
    return this.redisClient.quit();
  }

  async insert(userId: number, tokenId: string): Promise<void> {
    await this.redisClient.set(this.getKey(userId), tokenId);
  }

  async validate(userId: number, tokenId: string): Promise<boolean> {
    const storedId = await this.redisClient.get(this.getKey(userId));
    if (storedId !== tokenId) {
      throw new InvalidatedRefreshTokenError();
    }
    return storedId === tokenId;
  }

  async invalidate(userId: number): Promise<void> {
    await this.redisClient.del(this.getKey(userId));
  }

  private getKey(userId: number): string {
    return `user-${userId}`;
  }

  async refreshAccessToken(
    refreshToken: string,
  ): Promise<{ access_token: string }> {
    try {
      const decoded = await this.jwtService.verifyAsync(refreshToken);
      await this.refreshTokenIdsStorage.validate(decoded.sub, refreshToken);
      const payload = { sub: decoded.sub, username: decoded.username };
      const accessToken = await this.jwtService.signAsync(payload);
      return { access_token: accessToken };
    } catch (error) {
      this.logger.error(`Error: ${error.message}`);
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  async invalidateToken(accessToken: string): Promise<void> {
    try {
      const decoded = await this.jwtService.verifyAsync(accessToken);
      await this.refreshTokenIdsStorage.invalidate(decoded.sub);
    } catch (error) {
      throw new UnauthorizedException('Invalid access token');
    }
  }

}


@Injectable()
export class AuthService {
    constructor(
        private readonly usersService: UsersService,
        private readonly jwtService: JwtService,
      ) {}
    async create(registerUserDto: RegisterUserDto): Promise<User> {
        const { username, password } = registerUserDto;
    
        const salt = await bcrypt.genSalt();
        const hashedPassword = await bcrypt.hash(password, salt);
    
        const user = new User();
        user.username = username;
        user.password = hashedPassword;
    
        return this.userRepository.save(user);
      }

      async signIn(signInDto: SignInDto) {
        const { username, password } = signInDto;
    
        const user = await this.usersService.findByUsername(username);
    
        if (!user) {
          throw new UnauthorizedException('Invalid username or password');
        }
    
        const passwordIsValid = await user.validatePassword(password);
    
        if (!passwordIsValid) {
          throw new UnauthorizedException('Invalid username or password');
        }
    
        const payload = { sub: user.id, username: user.username };
        const accessToken = await this.jwtService.signAsync(payload);
    
        return { access_token: accessToken };
      }

      async findOne(id: number): Promise<User> {
        return this.userRepository.findOne(id);
    }
    
    async findByUsername(username: string): Promise<User> {
      return this.userRepository.findOne({ where: { username } });
    }

    
  async validateUser(username: string, password: string): Promise<any> {
    const user = await this.usersService.findByUsername(username);
    if (user && (await user.validatePassword(password))) {
      const { password, ...result } = user;
      return result;
    }
    return null;
  }
  async invalidateToken(accessToken: string): Promise<void> {
  try {
    const decoded = await this.jwtService.verifyAsync(accessToken);
    await this.refreshTokenIdsStorage.invalidate(decoded.sub);
  } catch (error) {
    throw new UnauthorizedException('Invalid access token');
  }
}
    

}
