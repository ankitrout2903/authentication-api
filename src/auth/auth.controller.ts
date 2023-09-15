import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { UsersService } from '../users/users.service';
import { Public } from './public.decorator';
import { LocalAuthGuard } from './local-auth.guard';
import { CreateUserDto } from '../users/create-user.dto';
import { RegisterUserDto } from '../users/register-user.dto';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly usersService: UsersService,
  ) {}

  
  @UseGuards(JwtRefreshTokenGuard)
  @Post('refresh-token')
  async refreshToken(@Body() refreshTokenDto: RefreshTokenDto) {
    return this.authService.refreshAccessToken(refreshTokenDto.refresh_token);
  }

  @UseGuards(JwtAuthGuard)
@Post('invalidate-token')
async invalidateToken(@Headers('authorization') authorization: string) {
  const token = authorization.split(' ')[1];
  await this.authService.invalidateToken(token);
  return { message: 'Token invalidated successfully' };
}

  @Public()
@Post('sign-in')
async signIn(@Body() signInDto: SignInDto) {
  return this.authService.signIn(signInDto);
}

@Public()
@Post('sign-up')
async signUp(@Body() createUserDto: CreateUserDto) {
  return this.authService.signUp(createUserDto);
}

@Public()
@UseGuards(LocalAuthGuard)
@Post('sign-in')
async signIn(@Request() req) {
  return this.authService.signIn(req.user);
}
}


