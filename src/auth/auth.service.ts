import { Injectable } from '@nestjs/common';

@Injectable()
export class AuthService {
    
    async create(registerUserDto: RegisterUserDto): Promise<User> {
        const { username, password } = registerUserDto;
    
        const salt = await bcrypt.genSalt();
        const hashedPassword = await bcrypt.hash(password, salt);
    
        const user = new User();
        user.username = username;
        user.password = hashedPassword;
    
        return this.userRepository.save(user);
      }

}
