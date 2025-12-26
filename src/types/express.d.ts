import { CurrentUserType } from './user.types';

declare module 'express' {
  export interface Request {
    user?: CurrentUserType;
  }
}
