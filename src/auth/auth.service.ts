import {
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/users/entities/user.entity';
import { Repository } from 'typeorm';
import * as argon2 from 'argon2';
import { JwtService } from '@nestjs/jwt';
import { SignUpDto } from './dto/sign.up.dto';
import { SignInDto } from './dto/sign.in.dto';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly jwtService: JwtService,
  ) {}

  async signUp(body: SignUpDto) {
    const userExists = await this.userRepository.findOne({
      where: { name: body.name },
    });
    if (!!userExists) {
      throw new ConflictException('User already exists');
    }
    const hashedPassword = await argon2.hash(body.password);
    const user = await this.userRepository.save({
      name: body.name,
      password: hashedPassword,
    });
    const tokens = await this.generateTokens(user.id, user.name);
    await this.updateRefreshToken(user, tokens.refreshToken);
    await this.userRepository.save(user);

    return tokens;
  }

  async signIn(body: SignInDto) {
    const user = await this.userRepository.findOne({
      where: { name: body.name },
    });
    if (!user) {
      throw new NotFoundException('User does not exist');
    }
    const isPasswordValid = await argon2.verify(user.password, body.password);
    if (!isPasswordValid) {
      throw new ConflictException('Invalid password');
    }
    const tokens = await this.generateTokens(user.id, user.name);
    await this.updateRefreshToken(user, tokens.refreshToken);
    await this.userRepository.save(user);

    return tokens;
  }

  async generateTokens(userId: number, name: string) {
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(
        {
          sub: userId,
          name,
        },
        {
          secret: 'access-token-secret',
          expiresIn: '15m',
        },
      ),
      this.jwtService.signAsync(
        {
          sub: userId,
          name,
        },
        {
          secret: 'refresh-token-secret',
          expiresIn: '7d',
        },
      ),
    ]);

    return {
      accessToken,
      refreshToken,
    };
  }

  async updateRefreshToken(user: User, refreshToken: string) {
    const hashedRefreshToken = await argon2.hash(refreshToken);
    user.refreshToken = hashedRefreshToken;
    await this.userRepository.save(user);
  }

  async refreshTokens(refreshToken: string, userId: number) {
    const user = await this.userRepository.findOne({
      where: { id: userId },
    });
    if (!user || !user.refreshToken) {
      throw new ForbiddenException('Access Denied');
    }
    const refreshTokenMatched = await argon2.verify(
      user.refreshToken,
      refreshToken,
    );
    if (!refreshTokenMatched) {
      throw new ForbiddenException('Access Denied');
    }
    const tokens = await this.generateTokens(user.id, user.name);
    await this.updateRefreshToken(user, tokens.refreshToken);
    return tokens;
  }
}
