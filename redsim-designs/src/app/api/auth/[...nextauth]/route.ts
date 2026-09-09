import NextAuth, { type AuthOptions } from "next-auth"
import KeycloakProvider from "next-auth/providers/keycloak"

/**
 * NextAuth + Keycloak OIDC. A real deployment sets KEYCLOAK_* env. In dev the
 * "Continue as dev admin" button on /login provides the token path instead
 * (hidden when NEXT_PUBLIC_REDSIM_ENV=prod). [spec §3, §18]
 */
export const authOptions: AuthOptions = {
  providers: [
    KeycloakProvider({
      clientId: process.env.KEYCLOAK_CLIENT_ID ?? "",
      clientSecret: process.env.KEYCLOAK_CLIENT_SECRET ?? "",
      issuer: process.env.KEYCLOAK_ISSUER ?? "",
    }),
  ],
  session: { strategy: "jwt" },
  pages: { signIn: "/login" },
}

const handler = NextAuth(authOptions)
export { handler as GET, handler as POST }
