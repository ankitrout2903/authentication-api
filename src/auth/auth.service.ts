import { Injectable } from '@nestjs/common';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { SignInDto } from './sign-in.dto';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from '../users/users.service';

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
    

}
