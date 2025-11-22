import NextAuth from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
import { authConfig } from './auth.config';
import { z } from 'zod';
import type { User } from '@/app/lib/definitions';
import bcrypt from 'bcrypt';
import postgres from 'postgres';
 
const sql = postgres(process.env.POSTGRES_URL!, { ssl: 'require' });
 
// ...
 
export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      async authorize(credentials) {
        // ...
 
        if (parsedCredentials.success) {
          const { email, password } = parsedCredentials.data;
          const user = await getUser(email);
          if (!user) return null;
          const passwordsMatch = await bcrypt.compare(password, user.password);
 
          if (passwordsMatch) return user;
        }
 
        console.log('Invalid credentials');
        return null;
      },
    }),
  ],
});