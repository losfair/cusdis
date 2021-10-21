import Providers, { AppProviders } from 'next-auth/providers'
import { prisma, resolvedConfig } from './utils.server'
import * as jwt from "jsonwebtoken";
import * as fs from "fs";
import { parse as parseCookie } from "cookie";

/**
 * Auth Providers
 * https://next-auth.js.org/configuration/providers
 */

const providers: AppProviders = []

if (resolvedConfig.useLocalAuth) {
  providers.push(
    Providers.Credentials({
      name: 'Username',
      credentials: {
        username: {
          label: 'Username',
          type: 'text',
          placeholder: 'env: USERNAME',
        },
        password: {
          label: 'Password',
          type: 'password',
          placeholder: 'env: PASSWORD',
        },
      },
      async authorize(credentials: { username: string; password: string }) {
        if (
          credentials.username === process.env.USERNAME &&
          credentials.password === process.env.PASSWORD
        ) {
          const user = await prisma.user.upsert({
            where: {
              id: credentials.username,
            },
            create: {
              id: credentials.username,
              name: credentials.username,
            },
            update: {
              id: credentials.username,
              name: credentials.username,
            },
          })
          return user
        } else {
          return null
        }
      },
    }),
  )
}

if (resolvedConfig.externalJwtPubkey) {
  const pem = fs.readFileSync(resolvedConfig.externalJwtPubkey, { encoding: "utf-8" });
  providers.push(
    Providers.Credentials({
      name: 'External JWT',
      credentials: {},
      async authorize(credentials: {}, req) {
        // `req.cookies` is empty
        const cookies = parseCookie(req.headers.cookie || "");
        const token = cookies[resolvedConfig.externalJwtCookieName];
        if(!token) {
          console.log("no cookie: " + resolvedConfig.externalJwtCookieName);
          return null;
        }

        let decoded: jwt.JwtPayload | string;
        try {
          decoded = jwt.verify(token, pem);
        } catch(e) {
          console.log(e);
          return null;
        }
        if(typeof decoded !== "object") {
          console.log("bad decoded jwt");
          return null;
        }
        const sub = decoded.sub;
        if(!sub) {
          console.log("no sub");
          return null;
        }

        const name = "" + (decoded.display_name || decoded.name || sub);

        if(Array.isArray(decoded.roles)) {
          if(decoded.roles.findIndex(x => x == "cusdis_user") != -1) {
            const user = await prisma.user.upsert({
              where: {
                id: sub,
              },
              create: {
                id: sub,
                name,
              },
              update: {
                id: sub,
                name,
              },
            })
            return user;
          }
        }

        console.log("no cusdis_user role");
        return null;
      }
    }),
  )
}

if (resolvedConfig.useGithub) {
  providers.push(
    Providers.GitHub({
      clientId: process.env.GITHUB_ID,
      clientSecret: process.env.GITHUB_SECRET,
      scope: 'read:user,user:email',
    }),
  )
}

if (resolvedConfig.google.id) {
  providers.push(
    Providers.Google({
      clientId: resolvedConfig.google.id,
      clientSecret: resolvedConfig.google.secret,
    }),
  )
}
export const authProviders = providers
