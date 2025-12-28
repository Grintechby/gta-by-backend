export enum UserRole {
  Admin = 'ADMIN',
  User = 'USER',
}

export interface CurrentUserType {
  id: number;
  name: string | null;
  email: string;
  role: UserRole;
}
